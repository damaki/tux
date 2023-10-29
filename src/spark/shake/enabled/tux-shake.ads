--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
private with Tux.Sponge_Keccak_1600_24;

with Tux.Types; use Tux.Types;

--  @summary
--  SHAKE128 and SHAKE256 definitions and subprograms.
--
--  @description
--  This package provides an implementation of SHAKE128 and SHAKE256 as defined
--  in NIST FIPS PUB 202.
--
--  @group XOF Algorithms
package Tux.SHAKE with
  Preelaborate,
  Elaborate_Body,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   type Algorithm_Kind is (SHAKE128, SHAKE256);
   --  Selects the SHAKE variant to use

   SHAKE128_Block_Length : constant Byte_Count := (1600 - (128 * 2)) / 8;
   --  Length of a SHAKE128 block in bytes

   SHAKE256_Block_Length : constant Byte_Count := (1600 - (256 * 2)) / 8;
   --  Length of a SHAKE256 block in bytes

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type State_Kind is (Updating, Extracting);
   --  Represents the current state of the SHAKE session.
   --
   --  @value Updating The SHAKE session is ready to accept input data.
   --  @value Extracting The SHAKE session is ready to generate output data.
   --                    Input data is no longer accepted in this state.

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited private;
   --  Holds the state for a multi-part SHAKE session.
   --
   --  @field Algorithm Selects the SHAKE algorithm to use.

   function Current_State (Ctx : Context) return State_Kind;
   --  Query the current state of the SHAKE session

   procedure Initialize (Ctx : out Context) with
     Inline,
     Relaxed_Initialization => Ctx,
     Post => Ctx'Initialized and Current_State (Ctx) = Updating;
   --  Start a new multi-part SHAKE hashing session.
   --
   --  This may be called at any time to abort an existing session and begin
   --  a new one.
   --
   --  @param Ctx The context to initialize.

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Inline,
     Pre  => Current_State (Ctx) = Updating,
     Post => Current_State (Ctx) = Updating;
   --  Process data in an ongoing SHAKE hashing session.
   --
   --  This may be called multiple times to process large amounts of data
   --  in several steps.
   --
   --  @param Ctx The SHAKE session context.
   --  @param Data Buffer containing the data to process in the SHAKE session

   procedure Extract
     (Ctx    : in out Context;
      Output :    out Byte_Array)
   with
     Relaxed_Initialization => Output,
     Post => Output'Initialized and Current_State (Ctx) = Extracting;
   --  Finish a SHAKE session and output the computed digest.
   --
   --  This may be called multiple times to generate an arbitrary-length
   --  output.
   --
   --  @param Ctx  The SHAKE session context.
   --  @param Hash Buffer to where the computed hash is written.

   procedure Sanitize (Ctx : out Context) with
     Inline,
     Relaxed_Initialization => Ctx,
     Post => Ctx'Initialized;
   --  Sanitize any potentially secret data held in a SHAKE session context.
   --
   --  @param Ctx The SHAKE session context to sanitize.

private
   use Tux.Sponge_Keccak_1600_24;

   type Context (Algorithm : Algorithm_Kind := Algorithm_Kind'First)
   is limited record
      case Algorithm is
         when SHAKE128 =>
            Ctx_128 : Sponge_Keccak_1600_24.Context (SHAKE128_Block_Length);

         when SHAKE256 =>
            Ctx_256 : Sponge_Keccak_1600_24.Context (SHAKE256_Block_Length);
      end case;
   end record;

   function Current_State (Ctx : Context) return State_Kind is
     (case Ctx.Algorithm is
        when SHAKE128 => (if Current_State (Ctx.Ctx_128) = Absorbing
                          then Updating
                          else Extracting),
        when SHAKE256 => (if Current_State (Ctx.Ctx_256) = Absorbing
                          then Updating
                          else Extracting));

end Tux.SHAKE;