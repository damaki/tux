--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This example demonstrates computing an HMAC over a multiple data buffers.

with Tux.Hashing;
with Tux.HMAC;
with Tux.Types;

procedure Example is
   Alg : constant Tux.Hashing.Enabled_Algorithm_Kind := Tux.Hashing.SHA256;
   --  The hash algorithm used with HMAC in this example (SHA-256)

   Key : constant Tux.Types.Byte_Array (1 .. 32) := (others => 0);
   --  Buffer containing the 256-bit authentication key to use (32 bytes)

   Data_1 : constant Tux.Types.Byte_Array := (1, 2, 3, 4, 5);
   --  Buffer containing the first data fragment to be authenticated

   Data_2 : constant Tux.Types.Byte_Array := (6, 7, 8, 9, 10);
   --  Buffer containing the second data fragment to be authenticated

   Len : constant Tux.HMAC.HMAC_Length_Number :=
           Tux.HMAC.HMAC_Length (Alg);
   --  Look up the length of the tag produced by HMAC-SHA-256 (32 bytes)

   MAC : Tux.Types.Byte_Array (1 .. Len);
   --  Buffer big enough to store the MAC

   Ctx : Tux.HMAC.Context (Alg);
   --  The context that holds the state of the multi-part HMAC operation
   --
   --  In this example we configure the HMAC context to use SHA-256 as the
   --  underlying hash function.

begin
   Tux.HMAC.Initialize (Ctx, Key);
   Tux.HMAC.Update (Ctx, Data_1);
   Tux.HMAC.Update (Ctx, Data_2);
   Tux.HMAC.Finish (Ctx, MAC);

   Tux.HMAC.Sanitize (Ctx);
end Example;
