/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "os.h"

#include "Dalvik.h"

#include <sys/time.h>
#include <sys/resource.h>
#include <limits.h>
#include <errno.h>

#include <cutils/sched_policy.h>
#include <utils/threads.h>

/*
 * 在linux中，线程优先级需要两个条件决定，一个是反映优先级的nice值，值越大优先级越低，在－20－19范围内，另一个条件是调度策略。
*/


/*
 * Conversion map for "nice" values.
 *
 * We use Android thread priority constants to be consistent with the rest
 * of the system.  In some cases adjacent entries may overlap.
 */
static const int kNiceValues[10] = {
    ANDROID_PRIORITY_LOWEST,                /* 1 (MIN_PRIORITY) */
    ANDROID_PRIORITY_BACKGROUND + 6,
    ANDROID_PRIORITY_BACKGROUND + 3,
    ANDROID_PRIORITY_BACKGROUND,
    ANDROID_PRIORITY_NORMAL,                /* 5 (NORM_PRIORITY) */
    ANDROID_PRIORITY_NORMAL - 2,
    ANDROID_PRIORITY_NORMAL - 4,
    ANDROID_PRIORITY_URGENT_DISPLAY + 3,
    ANDROID_PRIORITY_URGENT_DISPLAY + 2,
    ANDROID_PRIORITY_URGENT_DISPLAY         /* 10 (MAX_PRIORITY) */
};
/*
 *在linux中，调度优先级是通过nice值反映的，在andriod中如ANDROID_PRIORITY_BACKGROUND
 *更改线程的优先级来对应线程对象
 *首先新的nice值大于等于ANDROID_PRIORITY_BACKGROUND则需要改变线程调度策略为SP_BACKGROUND
 *若新的nice值小于ANDROID_PRIORITY_BACKGROUND并且当前线程nice值大于等于ANDROID_PRIORITY_BACKGROUND，则更改线程调度策略为SP_FOREGROUND
 *然后设置需要更改的线程优先级 setpriority
 */
void os_changeThreadPriority(Thread* thread, int newPriority)
{
    if (newPriority < 1 || newPriority > 10) {
        ALOGW("bad priority %d", newPriority);
        newPriority = 5;
    }

    int newNice = kNiceValues[newPriority-1];
    pid_t pid = thread->systemTid;

    if (newNice >= ANDROID_PRIORITY_BACKGROUND) {
        set_sched_policy(dvmGetSysThreadId(), SP_BACKGROUND);
    } else if (getpriority(PRIO_PROCESS, pid) >= ANDROID_PRIORITY_BACKGROUND) {
        set_sched_policy(dvmGetSysThreadId(), SP_FOREGROUND);
    }

    if (setpriority(PRIO_PROCESS, pid, newNice) != 0) {
        std::string threadName(dvmGetThreadName(thread));
        ALOGI("setPriority(%d) '%s' to prio=%d(n=%d) failed: %s",
        pid, threadName.c_str(), newPriority, newNice, strerror(errno));
    } else {
        ALOGV("setPriority(%d) to prio=%d(n=%d)", pid, newPriority, newNice);
    }
}

/*
 *通过查询系统权限获取当前线程的优先级
 *先获取系统权限sysprio，通过sysprio对比kNiceValues，获取到当前线程的优先级。
*/
int os_getThreadPriorityFromSystem()
{
    errno = 0;
    int sysprio = getpriority(PRIO_PROCESS, 0);
    if (sysprio == -1 && errno != 0) {
        ALOGW("getpriority() failed: %s", strerror(errno));
        return THREAD_NORM_PRIORITY;
    }

    int jprio = THREAD_MIN_PRIORITY;
    for (int i = 0; i < NELEM(kNiceValues); i++) {
        if (sysprio >= kNiceValues[i]) {
            break;
        }
        jprio++;
    }
    if (jprio > THREAD_MAX_PRIORITY) {
        jprio = THREAD_MAX_PRIORITY;
    }
    return jprio;
}

/*
 *调整当前线程优先级
 *若当前nice大于ANDROID_PRIORITY_NORMAL则说明权限很低，若nice大于等于ANDROID_PRIORITY_BACKGROUND则设置线程调度策略SP_FOREGROUND，设置当前线程nice值ANDROID_PRIORITY_NORMAL
 */
int os_raiseThreadPriority()
{
    /* Get the priority (the "nice" value) of the current thread.  The
     * getpriority() call can legitimately return -1, so we have to
     * explicitly test errno.
     */
    errno = 0;
    int oldThreadPriority = getpriority(PRIO_PROCESS, 0);
    if (errno != 0) {
        ALOGI("getpriority(self) failed: %s", strerror(errno));
    } else if (oldThreadPriority > ANDROID_PRIORITY_NORMAL) {
        /* Current value is numerically greater than "normal", which
         * in backward UNIX terms means lower priority.
         */
        if (oldThreadPriority >= ANDROID_PRIORITY_BACKGROUND) {
            set_sched_policy(dvmGetSysThreadId(), SP_FOREGROUND);
        }
        if (setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_NORMAL) != 0) {
            ALOGI("Unable to elevate priority from %d to %d",
                    oldThreadPriority, ANDROID_PRIORITY_NORMAL);
        } else {
            /*
             * The priority has been elevated.  Return the old value
             * so the caller can restore it later.
             */
            ALOGV("Elevating priority from %d to %d",
                    oldThreadPriority, ANDROID_PRIORITY_NORMAL);
            return oldThreadPriority;
        }
    }
    return INT_MAX;
}

/*
 *撤销os_raiseThreadPriority所更改的优先级
 *oldThreadPriority是oldThreadPriority返回的值，若大于等于ANDROID_PRIORITY_BACKGROUND则设置线程调度策略为SP_BACKGROUND
*/
void os_lowerThreadPriority(int oldThreadPriority)
{
    if (setpriority(PRIO_PROCESS, 0, oldThreadPriority) != 0) {
        ALOGW("Unable to reset priority to %d: %s",
                oldThreadPriority, strerror(errno));
    } else {
        ALOGV("Reset priority to %d", oldThreadPriority);
    }
    if (oldThreadPriority >= ANDROID_PRIORITY_BACKGROUND) {
        set_sched_policy(dvmGetSysThreadId(), SP_BACKGROUND);
    }
}
