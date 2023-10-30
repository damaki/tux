--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
pragma SPARK_Mode;

--  This stub implementation is used when SHA-256 is disabled in the crate
--  configuration. The purpose of this stub is to allow compilation against
--  this package so that facilities such as Tux.Hashing will still compile.

function Tux.SHA256.Self_Test return Boolean is
begin
   return False;
end Tux.SHA256.Self_Test;