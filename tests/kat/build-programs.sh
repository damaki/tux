#!/bin/bash

set -ex

(cd programs/hash ; alr build)
(cd programs/hkdf ; alr build)
(cd programs/hmac ; alr build)
(cd programs/xof ; alr build)
(cd programs/xof_monte ; alr build)