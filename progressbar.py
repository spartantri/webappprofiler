#!/usr/bin/env python
# -------------------------------------------------------------------------------
# Name:        Progress bar
# Purpose:     Script for printing progress bar
#
# Author:      spartantri
#
# Created:     20/08/2016
# Copyright:   (c) spartantri 2016
# License:     Apache License Version 2.0
# -------------------------------------------------------------------------------

import sys
import time


def draw_progress_bar(percent, start, message, barLen=20):
    sys.stdout.write("\r")
    progress = ""
    status = message
    for i in range(barLen):
        if i < int(barLen * percent):
            progress += "="
        else:
            progress += " "
    elapsedTime = time.time() - start
    try:
        estimatedRemaining = int((elapsedTime / percent) - elapsedTime)
    except ZeroDivisionError:
        estimatedRemaining = 0
    if percent == 1.0:
        sys.stdout.write("[ %s ] %.1f%% Elapsed: %im %02is ETA: Done!\n" %
            (progress, percent * 100, int(elapsedTime)/60, int(elapsedTime)%60))
        sys.stdout.flush()
        return
    else:
        sys.stdout.write("[ %s ] %.1f%% Elapsed: %im %02is ETA: %im%02is %s" %
            (progress, percent * 100, int(elapsedTime)/60, int(elapsedTime)%60,
             estimatedRemaining/60, estimatedRemaining%60, status))
        sys.stdout.flush()
        return


if __name__ == "__main__":
    percent = 0.0
    start = time.time()

    draw_progress_bar(percent, start, 'Starting ....')
    for x in xrange (1,301):
        percent = x/float(301)
        time.sleep(0.01)
        draw_progress_bar(percent, start, 'Item no# %d' % (x))
