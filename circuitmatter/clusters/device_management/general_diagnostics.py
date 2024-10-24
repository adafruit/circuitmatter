# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

from circuitmatter import data_model


class GeneralDiagnosticsCluster(data_model.Cluster):
    CLUSTER_ID = 0x0033
    cluster_revision = 2
