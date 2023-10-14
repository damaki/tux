--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This example demonstrates computing an HMAC over a single data buffer.

with Tux.Hashing;
with Tux.HMAC;
with Tux.Types;

procedure Example is
   Alg : constant Tux.Hashing.Enabled_Algorithm_Kind := Tux.Hashing.SHA256;
   --  The hash algorithm used with HMAC in this example (SHA-256)

   Key : constant Tux.Types.Byte_Array (1 .. 32) := (others => 0);
   --  Buffer containing the 256-bit authentication key to use (32 bytes)

   Data : constant Tux.Types.Byte_Array := (1, 2, 3, 4, 5);
   --  Buffer containing the data to be authenticated

   Len : constant Tux.HMAC.HMAC_Length_Number :=
           Tux.HMAC.HMAC_Length (Alg);
   --  Look up the length of the tag produced by HMAC-SHA-256 (32 bytes)

   MAC : Tux.Types.Byte_Array (1 .. Len);
   --  Buffer big enough to store the MAC

begin
   Tux.HMAC.Compute_HMAC (Alg, Key, Data, MAC);
end Example;
