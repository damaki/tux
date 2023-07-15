--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
pragma SPARK_Mode;

function Tux.SHA1.Self_Test return Boolean with
  Preelaborate,
  Annotate => (GNATprove, Terminating);
--  Perform a SHA-1 self test.
--
--  This runs the SHA-1 implementation against a small set of test vectors
--  to verify that the correct hashes are produced.
--
--  @return True if all test vectors passed, or False if any test failed.
