# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

from circuitmatter import data_model, tlv


class UserLabelCluster(data_model.Cluster):
    CLUSTER_ID = 0x0041
    cluster_revision = 1

    class LabelStruct(tlv.Structure):
        Label = tlv.UTF8StringMember(0, 16, default="")
        Value = tlv.UTF8StringMember(1, 16, default="")

    LabelList = data_model.ListAttribute(0x0000, LabelStruct, default=[], N_nonvolatile=True)
