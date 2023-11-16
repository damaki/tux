--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces; use Interfaces;

with Tux.Types; use Tux.Types;

--  @summary
--  Generic implementation of Keccak-f permutations.
--
--  @description
--  This package can be instantiated for the following Keccak-f permutations:
--   * Keccak-f[1600] (64-bit lanes)
--   * Keccak-f[800] (32-bit lanes)
--   * Keccak-f[400] (16-bit lanes)
--   * Keccak-f[200] (8-bit lanes)
generic
   type Lane_Type is mod <>;
   --  Type to use for an individual lane in the Keccak state.

   Lane_Size_Log : Positive;
   --  The binary logarithm of Lane_Type'Size
   --
   --  This determines the size of the Keccak-f state. Permitted values are:
   --  * Lane_Size_Log = 3 => 8-bit lanes, Keccak-f[200]
   --  * Lane_Size_Log = 4 => 16-bit lanes, Keccak-f[400]
   --  * Lane_Size_Log = 5 => 32-bit lanes, Keccak-f[800]
   --  * Lane_Size_Log = 6 => 64-bit lanes, Keccak-f[1600]

   with function To_Lane (Bytes : Byte_Array) return Lane_Type;
   --  Converts a byte array to a Keccak-f lane

   with procedure To_Bytes
     (Value :     Lane_Type;
      Bytes : out Byte_Array);
   --  Converts a lane to a byte array

   with function Rotate_Left
     (Value  : Lane_Type;
      Amount : Natural)
      return Lane_Type;
   --  Bitwise left rotate a lane

package Tux.Generic_Keccak with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   Lane_Size_Bytes : constant Byte_Count := Lane_Type'Size / Unsigned_8'Size;
   --  The size of a Keccak-f lane in bytes

   Context_Size_Bytes : constant Byte_Count :=
                          (Lane_Type'Size * 25) / Unsigned_8'Size;
   --  The size of the Keccak-f state in bytes

   type Round_Count is new Positive range 2 .. 24 with
     Predicate => Round_Count mod 2 = 0;
   --  Number of Keccak rounds.
   --
   --  The number of rounds is restricted to even numbers of rounds to
   --  simplify and optimize the implementation.

   type Context is private;
   --  The Keccak-f state

   procedure Initialize (Ctx : out Context);
   --  Initialize the Keccak-f state to all zeroes
   --
   --  @param Ctx The Keccak-f state to initialize.

   procedure XOR_Bytes_Into_Context
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Pre => (Data'Length <= Context_Size_Bytes
             and Data'Length mod Lane_Size_Bytes = 0);
   --  Bitwise XOR data into the Keccak-f state.
   --
   --  For simplicity and to reduce code size this procedure only supports
   --  writing whole lanes at a time. Data'Length must therefore be a multiple
   --  of Lane_Size_Bytes.
   --
   --  @param Ctx The Keccak-f state.
   --  @param Data The data to XOR into the Keccak-f state.

   procedure Extract_Bytes
     (Ctx  :     Context;
      Data : out Byte_Array)
   with
     Relaxed_Initialization => Data,
     Pre  => (Data'Length <= Context_Size_Bytes
              and Data'Length mod Lane_Size_Bytes = 0),
     Post => Data'Initialized;
   --  Read bytes from the Keccak-f state.
   --
   --  For simplicity and to reduce code size this procedure only supports
   --  reading whole lanes at a time. Data'Length must therefore be a multiple
   --  of Lane_Size_Bytes.
   --
   --  @param Ctx The Keccak-f state to read.
   --  @param Data Buffer to where the extracted bytes are written.

   generic
      Num_Rounds : Round_Count;
   procedure Generic_Permute (Ctx : in out Context);
   --  Apply the Keccak permutation to the internal state.
   --
   --  @param Ctx The Keccak-f state to permute.

   procedure Sanitize (Ctx : out Context);
   --  Sanitize the Keccak-f state to all zeroes
   --
   --  @param Ctx The Keccak-f state to sanitize.

private

   type X_Coord is mod 5;
   type Y_Coord is mod 5;

   type Context is array (X_Coord, Y_Coord) of Lane_Type;

end Tux.Generic_Keccak;