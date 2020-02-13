// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package run

import (
	"encoding/json"
	"os"
	"time"

	"github.com/elastic/cloud-on-k8s/test/e2e/test"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type eventLogEntry struct {
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type eventLogger struct {
	eventInformer         cache.SharedIndexInformer
	eventQueue            workqueue.RateLimitingInterface
	interestingNamespaces map[string]struct{}
	logFilePath           string
}

func newEventLogger(client *kubernetes.Clientset, testCtx test.Context, logFilePath string) *eventLogger {
	eventWatch := cache.NewListWatchFromClient(client.CoreV1().RESTClient(), "events", metav1.NamespaceAll, fields.Everything())
	el := &eventLogger{
		eventInformer:         cache.NewSharedIndexInformer(eventWatch, &corev1.Event{}, kubePollInterval, cache.Indexers{}),
		eventQueue:            workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "eck_e2e_events"),
		interestingNamespaces: make(map[string]struct{}),
		logFilePath:           logFilePath,
	}

	el.eventInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if key, err := cache.MetaNamespaceKeyFunc(obj); err == nil {
				el.eventQueue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj); err == nil {
				el.eventQueue.Add(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if key, err := cache.MetaNamespaceKeyFunc(newObj); err == nil {
				el.eventQueue.Add(key)
			}
		},
	})

	// add all namespaces to interesting namespaces
	s := struct{}{}
	el.interestingNamespaces[testCtx.E2ENamespace] = s
	el.interestingNamespaces[testCtx.Operator.Namespace] = s
	for _, ns := range testCtx.Operator.ManagedNamespaces {
		el.interestingNamespaces[ns] = s
	}

	return el
}

func (el *eventLogger) Start(stopChan <-chan struct{}) {
	defer func() {
		el.eventQueue.ShutDown()
		runtime.HandleCrash()
	}()

	go el.eventInformer.Run(stopChan)

	if !cache.WaitForCacheSync(stopChan, el.eventInformer.HasSynced) {
		log.Error(errors.New("timed out waiting for cache to sync"), "Failed to sync event cache")
		return
	}

	wait.Until(el.runEventProcessor, time.Second, stopChan)
}

func (el *eventLogger) runEventProcessor() {
	logFile, err := os.Create(el.logFilePath)
	if err != nil {
		log.Error(err, "Failed to create event log", "path", el.logFilePath)
		return
	}
	defer logFile.Close()
	logWriter := json.NewEncoder(logFile)

	for {
		key, quit := el.eventQueue.Get()
		if quit {
			return
		}

		evtObj, exists, err := el.eventInformer.GetIndexer().GetByKey(key.(string))
		if err != nil {
			log.Error(err, "Failed to get event", "key", key)
			return
		}

		if !exists {
			continue
		}

		evt := evtObj.(*corev1.Event)
		if el.isInterestingEvent(evt) {
			logEntry := eventLogEntry{
				Reason:    evt.Reason,
				Message:   evt.Message,
				Kind:      evt.InvolvedObject.Kind,
				Name:      evt.InvolvedObject.Name,
				Namespace: evt.InvolvedObject.Namespace,
			}
			if err := logWriter.Encode(logEntry); err != nil {
				log.Error(err, "Failed to write event to event log", "event", evt)
			}
		}
	}
}

// isInterestingEvent determines whether an event is worthy of logging.
func (el *eventLogger) isInterestingEvent(evt *corev1.Event) bool {
	// special case for event generated when attempting to reuse a deleted PV
	// This constant is defined in "k8s.io/kubernetes/pkg/controller/volume/events".VolumeDelete
	// but importing that with go modules is painful, see here:
	// https://github.com/golang/go/issues/32776#issuecomment-505607726
	// I did not see this defined anywhere else and nothing else in our code base uses the package, so seemed reasonable to copy/paste
	if evt.Reason == "VolumeDelete" {
		return true
	}

	// was the event generated by an object in one of the namespaces associated with this test run?
	if _, exists := el.interestingNamespaces[evt.InvolvedObject.Namespace]; exists {
		// if the event is a warning, it should be logged
		return evt.Type != corev1.EventTypeNormal
	}
	return false
}
