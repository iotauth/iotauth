{
  "source": "doc/api/timers.markdown",
  "modules": [
    {
      "textRaw": "Timers",
      "name": "timers",
      "stability": 3,
      "stabilityText": "Locked",
      "desc": "<p>All of the timer functions are globals.  You do not need to <code>require()</code>\nthis module in order to use them.\n\n</p>\n",
      "methods": [
        {
          "textRaw": "clearImmediate(immediateObject)",
          "type": "method",
          "name": "clearImmediate",
          "desc": "<p>Stops an immediate from triggering.\n\n</p>\n",
          "signatures": [
            {
              "params": [
                {
                  "name": "immediateObject"
                }
              ]
            }
          ]
        },
        {
          "textRaw": "clearInterval(intervalObject)",
          "type": "method",
          "name": "clearInterval",
          "desc": "<p>Stops an interval from triggering.\n\n</p>\n",
          "signatures": [
            {
              "params": [
                {
                  "name": "intervalObject"
                }
              ]
            }
          ]
        },
        {
          "textRaw": "clearTimeout(timeoutObject)",
          "type": "method",
          "name": "clearTimeout",
          "desc": "<p>Prevents a timeout from triggering.\n\n</p>\n",
          "signatures": [
            {
              "params": [
                {
                  "name": "timeoutObject"
                }
              ]
            }
          ]
        },
        {
          "textRaw": "ref()",
          "type": "method",
          "name": "ref",
          "desc": "<p>If you had previously <code>unref()</code>d a timer you can call <code>ref()</code> to explicitly\nrequest the timer hold the program open. If the timer is already <code>ref</code>d calling\n<code>ref</code> again will have no effect.\n\n</p>\n<p>Returns the timer.\n\n</p>\n",
          "signatures": [
            {
              "params": []
            }
          ]
        },
        {
          "textRaw": "setImmediate(callback[, arg][, ...])",
          "type": "method",
          "name": "setImmediate",
          "desc": "<p>To schedule the &quot;immediate&quot; execution of <code>callback</code> after I/O events\ncallbacks and before [<code>setTimeout</code>][] and [<code>setInterval</code>][]. Returns an\n<code>immediateObject</code> for possible use with <code>clearImmediate()</code>. Optionally you\ncan also pass arguments to the callback.\n\n</p>\n<p>Callbacks for immediates are queued in the order in which they were created.\nThe entire callback queue is processed every event loop iteration. If you queue\nan immediate from inside an executing callback, that immediate won&#39;t fire\nuntil the next event loop iteration.\n\n</p>\n",
          "signatures": [
            {
              "params": [
                {
                  "name": "callback"
                },
                {
                  "name": "arg",
                  "optional": true
                },
                {
                  "name": "...",
                  "optional": true
                }
              ]
            }
          ]
        },
        {
          "textRaw": "setInterval(callback, delay[, arg][, ...])",
          "type": "method",
          "name": "setInterval",
          "desc": "<p>To schedule the repeated execution of <code>callback</code> every <code>delay</code> milliseconds.\nReturns a <code>intervalObject</code> for possible use with <code>clearInterval()</code>. Optionally\nyou can also pass arguments to the callback.\n\n</p>\n<p>To follow browser behavior, when using delays larger than 2147483647\nmilliseconds (approximately 25 days) or less than 1, Node.js will use 1 as the\n<code>delay</code>.\n\n</p>\n",
          "signatures": [
            {
              "params": [
                {
                  "name": "callback"
                },
                {
                  "name": "delay"
                },
                {
                  "name": "arg",
                  "optional": true
                },
                {
                  "name": "...",
                  "optional": true
                }
              ]
            }
          ]
        },
        {
          "textRaw": "setTimeout(callback, delay[, arg][, ...])",
          "type": "method",
          "name": "setTimeout",
          "desc": "<p>To schedule execution of a one-time <code>callback</code> after <code>delay</code> milliseconds.\nReturns a <code>timeoutObject</code> for possible use with <code>clearTimeout()</code>. Optionally you\ncan also pass arguments to the callback.\n\n</p>\n<p>The callback will likely not be invoked in precisely <code>delay</code> milliseconds.\nNode.js makes no guarantees about the exact timing of when callbacks will fire,\nnor of their ordering. The callback will be called as close as possible to the\ntime specified.\n\n</p>\n<p>To follow browser behavior, when using delays larger than 2147483647\nmilliseconds (approximately 25 days) or less than 1, the timeout is executed\nimmediately, as if the <code>delay</code> was set to 1.\n\n</p>\n",
          "signatures": [
            {
              "params": [
                {
                  "name": "callback"
                },
                {
                  "name": "delay"
                },
                {
                  "name": "arg",
                  "optional": true
                },
                {
                  "name": "...",
                  "optional": true
                }
              ]
            }
          ]
        },
        {
          "textRaw": "unref()",
          "type": "method",
          "name": "unref",
          "desc": "<p>The opaque value returned by [<code>setTimeout</code>][] and [<code>setInterval</code>][] also has the\nmethod <code>timer.unref()</code> which will allow you to create a timer that is active but\nif it is the only item left in the event loop, it won&#39;t keep the program\nrunning. If the timer is already <code>unref</code>d calling <code>unref</code> again will have no\neffect.\n\n</p>\n<p>In the case of <code>setTimeout</code> when you <code>unref</code> you create a separate timer that\nwill wakeup the event loop, creating too many of these may adversely effect\nevent loop performance -- use wisely.\n\n</p>\n<p>Returns the timer.\n\n</p>\n",
          "signatures": [
            {
              "params": []
            }
          ]
        }
      ],
      "type": "module",
      "displayName": "Timers"
    }
  ]
}
