--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This example demonstrates computing a hash over a multiple data fragments.

with Tux.Hashing;
with Tux.Types;

procedure Example is
   Alg : constant Tux.Hashing.Enabled_Algorithm_Kind := Tux.Hashing.SHA256;
   --  The hash algorithm used in this example (SHA-256)

   Data_1 : constant Tux.Types.Byte_Array := (1, 2, 3, 4, 5);
   --  Buffer containing the first data fragment to be hashed

   Data_2 : constant Tux.Types.Byte_Array := (6, 7, 8, 9, 10);
   --  Buffer containing the second data fragment to be hashed

   Len : constant Tux.Hashing.Hash_Length_Number :=
           Tux.Hashing.Hash_Length (Alg);
   --  Look up the length of the SHA-256 hash (32 bytes)

   Hash : Tux.Types.Byte_Array (1 .. Len);
   --  Buffer big enough to store a SHA-256 hash

   Ctx : Tux.Hashing.Context (Alg);
   --  The context that holds the state of the multi-part hashing operation

begin
   Tux.Hashing.Initialize (Ctx);
   Tux.Hashing.Update (Ctx, Data_1);
   Tux.Hashing.Update (Ctx, Data_2);
   Tux.Hashing.Finish (Ctx, Hash);

   Tux.Hashing.Sanitize (Ctx);
end Example;
