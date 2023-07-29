--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Tux.Hashing;
with Tux.Types;   use Tux.Types;

--  @summary
--  Keyed-Hash Message Authentication Code (HMAC)
--
--  @group Authentication Algorithms
package Tux.HMAC with
  Preelaborate,
  SPARK_Mode,
  Annotate => (GNATprove, Terminating)
is

   subtype HMAC_Length_Number is Hashing.Hash_Length_Number;
   --  Represents the length of the MACs generated by an HMAC algorithm

   HMAC_Length : Hashing.Hash_Length_Table renames Hashing.Hash_Length;
   --  Lookup table of the HMAC tag lengths output by each HMAC algorithm.
   --
   --  The HMAC tag length is equal to the hash length of the underlying
   --  hash function used with HMAC.

   ---------------------------
   -- Multi-Part Operations --
   ---------------------------

   type Context (Algorithm : Hashing.Enabled_Algorithm_Kind)
   is limited private;
   --  Holds the state for a multi-part hashing session.
   --
   --  @field Algorithm Selects the hash algorithm to use.

   function Finished (Ctx : Context) return Boolean;
   --  Query whether the HMAC session is finished
   --
   --  @param Ctx The HMAC session context.
   --  @return True if the HMAC session is finished, False otherwise.

   procedure Initialize
     (Ctx : out Context;
      Key :     Byte_Array)
   with
     Pre  => Key'Length > 0,
     Post => not Finished (Ctx);
   --  Start a new multi-part HMAC session.
   --
   --  This may be called at any time to begin a new HMAC session.
   --
   --  @param Ctx The HMAC context to initialize.
   --  @param Key The secret authentication key to use for the HMAC session.

   procedure Update
     (Ctx  : in out Context;
      Data :        Byte_Array)
   with
     Pre  => not Finished (Ctx),
     Post => not Finished (Ctx);
   --  Process data in an ongoing HMAC session.
   --
   --  This may be called multiple times to process large amounts of data
   --  in several steps.
   --
   --  @param Ctx The HMAC session context.
   --  @param Data Buffer containing the data to process in the HMAC session.

   procedure Finish
     (Ctx : in out Context;
      MAC :    out Byte_Array)
   with
     Pre  => not Finished (Ctx) and MAC'Length = HMAC_Length (Ctx.Algorithm),
     Post => Finished (Ctx);
   --  Finish an HMAC session and generate the computed HMAC.
   --
   --  This procedure can be called only once per HMAC session.
   --  After calling this procedure, the HMAC session is finished and
   --  it is not possible to add new data to the session or (re)compute the
   --  HMAC. A new session can be started by calling Initialize again.
   --
   --  @param Ctx  The HMAC session context.
   --  @param MAC Buffer to where the computed MAC is written.

   procedure Finish_And_Verify
     (Ctx          : in out Context;
      Expected_MAC :        Byte_Array;
      Valid        :    out Boolean)
   with
     Pre  => (not Finished (Ctx)
              and Expected_MAC'Length in 1 .. HMAC_Length (Ctx.Algorithm)),
     Post => Finished (Ctx);
   --  Finish a HMAC session and compare the generated hash against an
   --  expected MAC.
   --
   --  This procedure can be called only once per HMAC session.
   --  After calling this procedure, the HMAC session is finished and
   --  it is not possible to add new data to the session or (re)compute the
   --  HMAC. A new session can be started by calling Initialize again.
   --
   --  @param Ctx The HMAC session context.
   --  @param Expected_MAC Buffer containing the expected MAC value.
   --                       If this is smaller than the generated MAC, then
   --                       only the first part of the generated MAC is
   --                       compared.
   --  @param Valid Set to True if the computed MAC exactly matches the
   --               expected MAC, or False otherwise.

   procedure Sanitize (Ctx : out Context) with
     Post => Finished (Ctx);
   --  Sanitize any potentially secret data held in an HMAC session context
   --
   --  @param Ctx The HMAC session context to sanitize.

   ----------------------------
   -- Single-Part Operations --
   ----------------------------

   procedure Compute_HMAC
     (Algorithm :     Hashing.Enabled_Algorithm_Kind;
      Key       :     Byte_Array;
      Data      :     Byte_Array;
      MAC       : out Byte_Array)
   with
     Pre => Key'Length > 0 and MAC'Length = HMAC_Length (Algorithm);
   --  Calculate the MAC of a message using HMAC.
   --
   --  @param Algorithm The hash algorithm to use for the HMAC calculation.
   --  @param Key The secret authentication key to use.
   --  @param Data The data to authenticate.
   --  @param MAC Buffer to where the calculated MAC is written.

   function Verify_HMAC
     (Algorithm    : Hashing.Enabled_Algorithm_Kind;
      Key          : Byte_Array;
      Data         : Byte_Array;
      Expected_MAC : Byte_Array)
      return Boolean
   with
     Pre => Key'Length > 0 and
            Expected_MAC'Length in 1 .. HMAC_Length (Algorithm);
   --  Verify the MAC of a message using HMAC.
   --
   --  @param Algorithm The hash algorithm to use for the HMAC calculation.
   --  @param Key The secret authentication key to use.
   --  @param Data The data to authenticate.
   --  @param Expected_MAC Buffer containing the MAC to compare against the
   --                      calculated MAC. If this buffer is smaller than the
   --                      calculated MAC then the first part of the calculated
   --                      MAC is compared.
   --  @return True if the calculated MAC exactly matches the Expected_MAC,
   --          or False otherwise.

private
   use type Hashing.Enabled_Algorithm_Kind;

   type Context (Algorithm : Hashing.Enabled_Algorithm_Kind)
   is limited record
      Inner_Ctx : Hashing.Context (Algorithm);
      Outer_Ctx : Hashing.Context (Algorithm);
   end record;

   function Finished (Ctx : Context) return Boolean is
     (Hashing.Finished (Ctx.Inner_Ctx) or Hashing.Finished (Ctx.Outer_Ctx));

end Tux.HMAC;
