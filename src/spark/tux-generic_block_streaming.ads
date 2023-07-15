--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Types; use Tux.Types;

--  @summary
--  Splits a byte stream into fixed-size blocks for processing
--
--  @description
--  This package is intended for use in constructions such as hash functions
--  which split an incoming byte stream into fixed-size blocks then apply a
--  compression function to each block.
generic
   type Internal_State_Type is limited private;
   --  Type of the internal state passed to Process_Blocks

   with procedure Process_Blocks
     (State  : in out Internal_State_Type;
      Blocks :        Byte_Array);
   --  Processes one or more fixed-size blocks of data into some internal
   --  state.
   --
   --  Blocks'Length is always a multiple of Block_Length when this procedure
   --  is called.

   Block_Length : Byte_Count;
   --  The length of each fixed-size block in bytes

package Tux.Generic_Block_Streaming with
  Preelaborate,
  Annotate => (GNATprove, Terminating)
is

   subtype Partial_Block_Length_Number is Natural range 0 .. Block_Length - 1;

   type Context is record
      Partial_Block : Byte_Array (0 .. Block_Length - 1) := (others => 0);
      --  Buffers any leftovers until we have a complete block

      Partial_Block_Length : Partial_Block_Length_Number := 0;
      --  Number of bytes stored in Partial_Block
   end record;

   procedure Sanitize (Ctx : out Context);

   procedure Initialize (Ctx : out Context) renames Sanitize;

   procedure Update
     (Ctx   : in out Context;
      Data  :        Byte_Array;
      State : in out Internal_State_Type);
   --  Process an arbitrary number of bytes
   --
   --  Once one or more complete blocks are obtained they are passed to
   --  Process_Blocks. Any leftovers (partial blocks) are buffered to be
   --  appended to the data in the next call to this procedure.
   --
   --  @param Ctx   The context.
   --  @param Data  The data to process.
   --  @param State The internal state passed to Process_Blocks.

end Tux.Generic_Block_Streaming;
