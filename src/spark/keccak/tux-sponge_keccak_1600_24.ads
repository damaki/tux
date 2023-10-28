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
   Permutation_Context     => Tux.Keccak_1600.Context,
   Initialize              => Tux.Keccak_1600.Initialize,
   Sanitize                => Tux.Keccak_1600.Sanitize,
   XOR_Bytes_Into_Context  => Tux.Keccak_1600.XOR_Bytes_Into_Context,
   Extract_Bytes           => Tux.Keccak_1600.Extract_Bytes,
   Permutation_Round_Count => Tux.Keccak_1600.Round_Count,
   Num_Rounds              => 24,
   Permute                 => Tux.Keccak_1600.Permute,
   Pad_With_Suffix         => Tux.Padding.Pad101_With_Suffix,
   Padding_Min_Bits        => Tux.Padding.Pad101_Min_Bits,
   Rate_Multiple           => Tux.Keccak_1600.Lane_Size_Bytes);