--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux_Config; use Tux_Config;
with Tux.Types;  use Tux.Types;

with Tux.SHAKE;

--  @summary
--  Wrapper around hash functions.
--
--  @description
--  This package provides a convenient wrapper around the supported hash
--  functions, allowing run-time selection of hash algorithms.
--
--  @group XOF Algorithms
package Tux.XOF with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   ------------------------
   -- XOF Algorithm IDs --
   ------------------------

   type Algorithm_Kind is
     (SHAKE128, --  SHAKE128
      SHAKE256  --  SHAKE256
     );
   --  The set of XOF algorithms that are supported in this package.
   --
   --  Note that some XOF functions might be disabled via the crate
   --  configuration. The set of enabled XOF algorithms is represented
   --  by the Enabled_Algorithm_Kind type.

   --------------------------------
   -- Enabled Hash Algorithm IDs --
   --------------------------------

   SHAKE_Disabled : constant Boolean := not Tux_Config.SHAKE_Enabled;
   --  @private

   pragma Warnings
     (Off, "predicate is redundant",
      Reason => "Predicate depends on the crate configuration");

   subtype Enabled_Algorithm_Kind is Algorithm_Kind with
     Dynamic_Predicate =>
       (if SHAKE_Disabled then Enabled_Algorithm_Kind not in
                                 SHAKE128 | SHAKE256);
   --  The set of XOF algorithms that are enabled in the crate configuration.
   --
   --  The predicate on this type prohibits all XOF algorithms that are
   --  disabled in the crate configuration.

   pragma Warnings (On);

   --------------------
   -- XOF Attributes --
   --------------------

   subtype Block_Length_Number is Byte_Count range 136 .. 168;
   --  Represents the block size of a XOF

   type Block_Length_Table is array (Algorithm_Kind) of Block_Length_Number;
   --  Maps a XOF algorithm enum to its corresponding block length

   Block_Length : constant Block_Length_Table :=
     (SHAKE128 => Tux.SHAKE.SHAKE128_Block_Length,
      SHAKE256 => Tux.SHAKE.SHAKE256_Block_Length);
   --  Lookup table of the block size of each XOF algorithm

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type State_Kind is (Updating, Extracting);

   type Context (Algorithm : Enabled_Algorithm_Kind) is limited private;
   --  Holds the state for a multi-part XOF session.
   --
   --  @field Algorithm Selects the XOF algorithm to use.

   function Current_State (Ctx : Context) return State_Kind;

   procedure Initialize (Ctx : out Context) with
     Relaxed_Initialization => Ctx,
     Post => Ctx'Initialized and Current_State (Ctx) = Updating;
   --  Start a new multi-part XOF session.
   --
   --  This may be called at any time to abort an existing session and begin
   --  a new one.
   --
   --  @param Ctx The context to initialize.

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Pre  => Current_State (Ctx) = Updating,
     Post => Current_State (Ctx) = Updating;
   --  Process data in an ongoing XOF session.
   --
   --  This may be called multiple times to process large amounts of data
   --  in several steps.
   --
   --  @param Ctx The XOF session context.
   --  @param Data Buffer containing the data to process in the XOF session

   procedure Extract
     (Ctx    : in out Context;
      Digest :    out Byte_Array)
   with
     Relaxed_Initialization => Digest,
     Post => Digest'Initialized and Current_State (Ctx) = Extracting;
   --  Generate variable-length output from the XOF.
   --
   --  This may be called multiple times to generate an arbitrary-length
   --  output.
   --
   --  @param Ctx  The XOF session context.
   --  @param Hash Buffer to where the computed digest is written.

   procedure Extract_And_Verify
     (Ctx             : in out Context;
      Expected_Digest :        Byte_Array;
      Valid           :    out Boolean)
   with
     Pre  => Expected_Digest'Length > 0,
     Post => Current_State (Ctx) = Extracting;
   --  Generate output from the XOF and compare the output against an expected
   --  digest.
   --
   --  This may be called multiple times to verify an arbitrary-length digest.
   --
   --  @param Ctx The XOF session context.
   --  @param Expected_Hash Buffer containing the expected digest value.
   --                       If this is smaller than the generated digest, then
   --                       only the first part of the generated digest is
   --                       compared.
   --  @param Valid Set to True if the computed digest exactly matches the
   --               expected digest, or False otherwise.

   procedure Sanitize (Ctx : out Context) with
     Relaxed_Initialization => Ctx,
     Post => Ctx'Initialized;
   --  Sanitize any potentially secret data held in a XOF session context.
   --
   --  @param Ctx The XOF session context to sanitize.

   ----------------------------
   -- Single-Part Operations --
   ----------------------------

   procedure Compute_Digest
     (Algorithm :     Enabled_Algorithm_Kind;
      Data      :     Byte_Array;
      Digest    : out Byte_Array);
   --  Compute the XOF digest digest over a buffer.
   --
   --  @param Algorithm Selects the XOF algorithm to use.
   --  @param Data Buffer containing the data to process.
   --  @param Digest Buffer to where the computed digest is written.

   function Verify_Digest
     (Algorithm       : Enabled_Algorithm_Kind;
      Data            : Byte_Array;
      Expected_Digest : Byte_Array)
      return Boolean
   with
     Pre => Expected_Digest'Length > 0;
   --  Compute a digest over a buffer and compare the digest against an
   --  expected digest value.
   --
   --  @param Algorithm       Selects the XOF algorithm to use.
   --  @param Data            Buffer containing the data to process.
   --  @param Expected_Digest Buffer containing the expected digest.
   --                         If this is smaller than the generated digest,
   --                         then only the first part of the generated digest
   --                         is compared.
   --  @return True if the generated digest exactly matches the expected digest
   --          or False otherwise.

private
   type Context (Algorithm : Enabled_Algorithm_Kind) is limited record
      case Algorithm is
         when SHAKE128 =>
            SHAKE128_Ctx : Tux.SHAKE.Context (Tux.SHAKE.SHAKE128);
         when SHAKE256 =>
            SHAKE256_Ctx : Tux.SHAKE.Context (Tux.SHAKE.SHAKE256);
      end case;
   end record;

   function XOF_State (State : Tux.SHAKE.State_Kind) return State_Kind is
     (case State is
         when SHAKE.Updating   => Updating,
         when SHAKE.Extracting => Extracting);
   --  Map a SHAKE State_Kind to its equivalent XOF State_Kind

   function Current_State (Ctx : Context) return State_Kind is
     (case Ctx.Algorithm is
        when SHAKE128 => XOF_State (SHAKE.Current_State (Ctx.SHAKE128_Ctx)),
        when SHAKE256 => XOF_State (SHAKE.Current_State (Ctx.SHAKE256_Ctx)));

end Tux.XOF;
