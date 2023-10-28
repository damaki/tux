--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces; use Interfaces;

with Tux.Types; use Tux.Types;

--  @summary
--  Implements the cryptographic sponge construction.
--
--  @description
--  The sponge construction is a simple iterated construction for processing
--  variable-length input and producing an arbitrary output length based on a
--  fixed-length cryptographic permutation.
--
--  The sponge has two phases: absorbing and squeezing. In the absorbing phase
--  an arbitrary number of input bytes are input ("absorbed") into the sponge.
--  In the squeezing phase, an arbitrary number of bytes are output
--  ("squeezed") from the sponge.
--
--  This implementation supports bytewise messages only, i.e. where the length
--  of the input and output data are a multiple of 8 bits. During the
--  transition from the absorbing phase to the squeezing phase there is the
--  opportunity to absorb any optional suffix bits to the input data prior to
--  moving to the squeezing phase.
generic
   Permutation_Size : Byte_Count;
   --  The size of the permutation's internal state in bytes

   type Permutation_Context is private;
   --  The permutation internal state

   with procedure Initialize (Ctx : out Permutation_Context);
   --  Initializes the permutation's internal state

   with procedure Sanitize (Ctx : out Permutation_Context);
   --  Sanitize the permutation's internal state

   with procedure XOR_Bytes_Into_Context
     (Ctx  : in out Permutation_Context;
      Data :        Tux.Types.Byte_Array);
   --  XOR a block of data into the start of the permutation's internal state

   with procedure Extract_Bytes
     (Ctx  :     Permutation_Context;
      Data : out Tux.Types.Byte_Array);
   --  Read bytes from the start of the permutation's internal state

   type Permutation_Round_Count is range <>;
   --  Number of rounds in the permutation function.
   --
   --  This is used for permutation functions that have a configurable
   --  number of rounds. For permutations with a fixed number of rounds this
   --  can be defined as a type with only one value in its range. For example:
   --
   --     type Round_Count is range 24 .. 24;

   Num_Rounds : Permutation_Round_Count;

   with procedure Permute
     (Ctx        : in out Permutation_Context;
      Num_Rounds :        Permutation_Round_Count);
   --  Permute the internal state

   with procedure Pad_With_Suffix
     (Buffer      : out Byte_Array;
      Suffix      :     Unsigned_8;
      Suffix_Bits :     Natural);
   --  Combine any suffix bits (up to 8 - Padding_Min_Bits bits) with the
   --  multi-rate padding rule into the supplied buffer.

   Padding_Min_Bits : Natural;
   --  Minimum number of bits that are added to the padding.
   --
   --  This value must be in the range 0 .. 7.

   Rate_Multiple : Positive;
   --  Constrains the sponge rate parameter to be a multiple of this size.
   --
   --  This is useful when the XOR_Bytes_Into_State and/or Extract_Bytes
   --  procedures have preconditions that require their buffers to be a
   --  multiple of a specific size.
   --
   --  Set this parameter to 1 when there are no such restrictions.

package Tux.Generic_Sponge with
  Preelaborate,
  Annotate => (GNATprove, Terminating)
is

   subtype Rate_Number is Byte_Count range 1 .. Permutation_Size with
     Dynamic_Predicate => Rate_Number mod Rate_Multiple = 0;
   --  The rate of a sponge function in bytes.

   subtype Suffix_Bit_Count is Natural
     range 0 .. Unsigned_8'Size - Padding_Min_Bits;
   --  The number of suffix bits that can be appended to a message.
   --
   --  The maximum number of suffix bits depends on the minimum number of bits
   --  needed by the padding function. For example, the pad10*1 padding rule
   --  requires a minimum of 2 bits, which leaves up to 6 bits for the suffix.

   type State_Kind is (Absorbing, Squeezing);
   --  The current state of the sponge.
   --
   --  @value Absorbing The sponge is in the absorbing phase where
   --                   abitrary-length bytes are being input into the sponge.
   --  @value Squeezing The sponge is in the squeezing phase where
   --                   abitrary-length bytes are being output from the sponge.

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type Context (Rate : Rate_Number) is private;
   --  Holds the state for a multi-part sponge processing session.
   --
   --  @field Rate The rate of the sponge in bytes. The rate is calculated as
   --              the permutation size minus the capacity (2x the desired
   --              security parameter). For example, for Keccak-1600 with
   --              256-bit security:
   --               * Permutation_Size = 200 bytes (1600 bits),
   --               * Capacity = 64 bytes (256 * 2 bits), and
   --               * Rate = 200 - 64 = 136 bytes (1088 bits)

   function Current_State (Ctx : Context) return State_Kind;
   --  Get the current state of the sponge (absorbing or squeezing)

   procedure Initialize (Ctx : out Context) with
     Post => Current_State (Ctx) = Absorbing;
   --  Start a new sponge session.
   --
   --  @param Ctx The sponge context to initialize.

   procedure Absorb
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Pre  => Current_State (Ctx) = Absorbing,
     Post => Current_State (Ctx) = Absorbing;
   --  Absorb an arbitrary number of bytes into the sponge.
   --
   --  This may be called multiple times during the absorption phase to process
   --  large amounts of data in several steps.
   --
   --  @param Ctx The sponge context.
   --  @param Data Buffer containing the data to process in the sponge session.

   procedure Prepare_Squeeze
     (Ctx         : in out Context;
      Suffix      :        Unsigned_8;
      Suffix_Bits :        Suffix_Bit_Count)
   with
     Pre  => (Current_State (Ctx) = Absorbing
              and Natural (Suffix) < 2**Suffix_Bits),
     Post => Current_State (Ctx) = Squeezing;
   --  Transition the sponge to the squeezing phase.
   --
   --  Any optional message suffix bits can be absorbed at this point.
   --  If no suffix is required, then set Suffix and Suffix_Bits to zero.
   --
   --  @param Ctx         The sponge context to move to the squeezing phase.
   --  @param Suffix      Optional suffix bits to append to the message.
   --  @param Suffix_Bits The number of suffix bits to append.

   procedure Squeeze
     (Ctx  : in out Context;
      Data :    out Byte_Array)
   with
     Relaxed_Initialization => Data,
     Pre  => Current_State (Ctx) = Squeezing,
     Post => Current_State (Ctx) = Squeezing and Data'Initialized;
   --  Squeeze and arbitrary number of bytes from the sponge.
   --
   --  This may be called multiple times during the squeezing phase to extract
   --  large amounts of data in several steps.
   --
   --  @param Ctx The sponge context.
   --  @param Data Buffer to store the output data from the sponge. The length
   --              of this buffer determines the number of bytes that are
   --              squeezed.

   procedure Sanitize (Ctx : out Context) with
     Post => Current_State (Ctx) = Squeezing;
   --  Sanitize any potentially secret data held in an sponge session context
   --
   --  @param Ctx The sponge session context to sanitize.

private

   type Context (Rate : Rate_Number) is record
      Internal_State : Permutation_Context;
      --  The permutation function's internal state

      Length : Byte_Count := 0;
      --  During the absorbing phase this is the length of any partial block
      --  stored in the Buffer.
      --
      --  During the squeezing phase this is the number of bytes that have
      --  already been read out of the current block (stored in the Buffer).
      --  The number of remaining (unread) bytes in the current block stored in
      --  the Buffer is calculated by: Ctx.Rate - Length.

      State : State_Kind := Absorbing;
      --  Determines whether the sponge is currently in the absorbing or
      --  squeezing phase.

      Buffer : Byte_Array (1 .. Rate);
      --  Stores the content of any partial block during the absorbing or
      --  squeezing phase.

   end record with
     Type_Invariant => (case State is
                           when Absorbing => Length in 0 .. Rate - 1,
                           when Squeezing => Length in 0 .. Rate);

   function Current_State (Ctx : Context) return State_Kind is (Ctx.State);

end Tux.Generic_Sponge;