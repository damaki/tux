--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--

--  This example demonstrates computing a hash over a single data buffer.

with Tux.Hashing;
with Tux.Types;

procedure Example is
   Algorithm : constant Tux.Hashing.Enabled_Algorithm_ID := Tux.Hashing.SHA256;
   --  The hash algorithm used in this example (SHA-256)

   Data : constant Tux.Types.Byte_Array := (1, 2, 3, 4, 5);
   --  Buffer containing the data to be hashed

   Len : constant Tux.Hashing.Hash_Length_Number :=
           Tux.Hashing.Hash_Length (Algorithm);
   --  Look up the length of the SHA-256 hash (32 bytes)

   Hash : Tux.Types.Byte_Array (1 .. Len);
   --  Buffer big enough to store a SHA-256 hash

begin
   Tux.Hashing.Compute_Hash (Algorithm, Data, Hash);
end Example;
