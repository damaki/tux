--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
pragma SPARK_Mode (On);

with Tux.Keccak_1600;
with Tux.Generic_Sponge;
with Tux.Padding;

--  @summary
--  Sponge instance based on Keccak-p[1600, 24] and the pad10*1 padding rule
package Tux.Sponge_Keccak_1600_24 is new Tux.Generic_Sponge
  (Permutation_Size        => 1600 / 8,
   Permutation_Context     => Tux.Keccak_1600.Keccak.Context,
   Initialize              => Tux.Keccak_1600.Keccak.Initialize,
   Sanitize                => Tux.Keccak_1600.Keccak.Sanitize,
   XOR_Bytes_Into_Context  => Tux.Keccak_1600.Keccak.XOR_Bytes_Into_Context,
   Extract_Bytes           => Tux.Keccak_1600.Keccak.Extract_Bytes,
   Permute                 => Tux.Keccak_1600.Permute_24,
   Pad_With_Suffix         => Tux.Padding.Pad101_With_Suffix,
   Padding_Min_Bits        => Tux.Padding.Pad101_Min_Bits,
   Rate_Multiple           => Tux.Keccak_1600.Keccak.Lane_Size_Bytes);