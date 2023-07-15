--
--  Copyright 2023 (C) Daniel King
--
--  SPDX-License-Identifier: Apache-2.0
--
with Interfaces; use Interfaces;

package Support.Timing is

   subtype Cycles_Count is Unsigned_64;

   type Time is private;

   procedure Calibrate;

   procedure Start_Measurement (T : out Time);

   function End_Measurement (T : Time) return Cycles_Count;

private

   type Time is new Cycles_Count;

end Support.Timing;
