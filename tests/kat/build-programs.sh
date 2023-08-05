#!/bin/bash

set -ex

(cd programs/hash ; alr build)
(cd programs/hkdf ; alr build)
(cd programs/hmac ; alr build)