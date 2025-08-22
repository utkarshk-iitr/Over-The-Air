#!/usr/bin/env python3
import random
import time
import string
import os
import csv
from merkle import *

try:
    import pyexcel as pe
    PYEXCEL_AVAILABLE = True
except Exception:
    PYEXCEL_AVAILABLE = False

class TrustedAuthority:
    def __init__(self, save_path_ta="FRI_TA_Reg.xlsx"):
        self.regs = []
        self.save_path_ta = save_path_ta
        if PYEXCEL_AVAILABLE:
            try:
                _ = pe.get_sheet(file_name=self.save_path_ta)
            except Exception:
                s = pe.Sheet()
                s.name_columns_by_row(0)
                s.row += ["VID", "VPR", "alpha", "R_reg", "MR_fx", "MR_fstar", "TA_comp_time", "reg_latency","Version"]
                s.save_as(self.save_path_ta)

    def process_initial(self, vid_rpr_mrfx_t1: str) -> str:
        start = time.time()
        parts = vid_rpr_mrfx_t1.split("&")
        if len(parts) < 4:
            raise ValueError("Invalid initial message to TA")
        VID, VPR, MR_fx, T1s = parts[0], parts[1], parts[2], parts[3]
        T1 = float(T1s)
        if get_timestamp() - T1 >= 4:
            raise TimeoutError("T1 timestamp check failed at TA")
        alpha = random.randint(0, 16)
        R_reg = random.randint(100, 100000)
        T2 = get_timestamp()
        self._pending = {"VID": VID, "VPR": VPR, "MR_fx": MR_fx, "alpha": alpha, "R_reg": R_reg, "T1": T1, "T2": T2}
        response = f"{alpha}&{R_reg}&{T2}"
        return response

    def verify_registration(self, r_reg_mr_fstar_t3: str) -> str:
        start = time.time()
        parts = r_reg_mr_fstar_t3.split("&")
        if len(parts) < 3:
            raise ValueError("Invalid verification message to TA")
        R_reg_star = int(parts[0])
        MR_fstar = parts[1]
        T3 = float(parts[2])
        pending = getattr(self, "_pending", None)
        if pending is None:
            print("TA: no pending registration")
            return "F"
        
        if get_timestamp() - T3 < 4 and pending["R_reg"] == R_reg_star:
            TA_comp_time = time.time() - start
            reg_latency = T3 - pending["T1"] if T3 > pending["T1"] else 0.0
            row = [pending["VID"], pending["VPR"], pending["alpha"], pending["R_reg"], pending["MR_fx"], MR_fstar, TA_comp_time, reg_latency,"1.0.0"]
            self.regs.append(row)
            if PYEXCEL_AVAILABLE:
                try:
                    sheet = pe.get_sheet(file_name=self.save_path_ta)
                    sheet.row += row
                    sheet.save_as(self.save_path_ta)
                except Exception:
                    self._save_csv("FRI_TA_Reg.csv", row)
            else:
                self._save_csv("FRI_TA_Reg.csv", row)
            return "S"
        else:
            print("TA: Reg failed (timestamp or R_reg mismatch)")
            return "F"

    def _save_csv(fname, row):
        header_needed = not os.path.exists(fname)
        with open(fname, "a", newline="") as f:
            writer = csv.writer(f)
            if header_needed:
                writer.writerow(["VID", "VPR", "alpha", "R_reg", "MR_fx", "MR_fstar", "TA_comp_time", "reg_latency","Version"])
            writer.writerow(row)


def run_manufacturer(ta, save_path_veh="FRI_Veh_Reg.xlsx"):
    prime_field = 17
    w_i = [1, 7, 15, 3, 4, 11, 9, 12, 16, 10, 2, 14, 13, 6, 8, 5]
    w_2i = [1, 15, 4, 9, 16, 2, 13, 8]
    ID_size = 7

    if PYEXCEL_AVAILABLE:
        try:
            _ = pe.get_sheet(file_name=save_path_veh)
        except Exception:
            s = pe.Sheet()
            s.name_columns_by_row(0)
            s.row += ["f_coeffs", "VID", "VPR", "f_w_i", "f_star_w_2i", "veh_comp_time11", "veh_comp_time"]
            s.save_as(save_path_veh)

    start1 = time.time()
    VID = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(ID_size))
    PIN = "".join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(ID_size))
    print("VID : ", VID)

    r = random.randint(100, 100000)
    VPR = hashlib.sha256(VID.encode("utf-8") + PIN.encode("utf-8") + str(r).encode("utf-8")).hexdigest()

    fx_list = []
    f_deg = random.randint(6, 12)
    for _ in range(0, f_deg + 1):
        fx_list.append(random.randint(-100, 100))
    fx_list.reverse()

    f_w_i = [evaluate_polynomial(fx_list, each) % prime_field for each in w_i]
    MR_fx, _ = mixmerkletree([str(x) for x in f_w_i])

    fo_list = []
    fe_list = []
    deg = len(fx_list)
    i = 0
    if deg % 2 == 0:
        while i < len(fx_list) - 2:
            fo_list.append(fx_list[i])
            i += 1
            fe_list.append(fx_list[i])
            i += 1
        if i == len(fx_list) - 2:
            fo_list.append(fx_list[i])
            i += 1
            fe_list.append(fx_list[i])
    else:
        while i < len(fx_list) - 2:
            fe_list.append(fx_list[i])
            i += 1
            if i == len(fx_list) - 2:
                fo_list.append(fx_list[i])
                i += 1
                fe_list.append(fx_list[i])
            else:
                fo_list.append(fx_list[i])
                i += 1

    fe_w_2i = [evaluate_polynomial(fe_list, each) % prime_field for each in w_2i]
    fo_w_2i = [evaluate_polynomial(fo_list, each) % prime_field for each in w_2i]

    T1 = str(get_timestamp())
    VID_RPR_MRfx_T1 = VID + "&" + VPR + "&" + MR_fx + "&" + T1
    veh_comp_time = time.time() - start1

    ta_response = ta.process_initial(VID_RPR_MRfx_T1)
    alpha_str, R_reg_str, T2_str = ta_response.split("&")
    alpha = int(alpha_str)
    R_reg = R_reg_str
    T2 = T2_str

    if get_timestamp() - float(T2) < 4:
        f_star_w_2i = []
        f_star_len = len(w_2i)
        for i in range(f_star_len):
            f_star_w_2i.append((fe_w_2i[i] + alpha * fo_w_2i[i]) % prime_field)

        MR_fstar, _ = mixmerkletree([str(x) for x in f_star_w_2i])
        T3 = get_timestamp()
        veh_comp_time += (time.time() - start1) - veh_comp_time

        R_reg_MR_fstar_T3 = str(R_reg) + "&" + MR_fstar + "&" + str(T3)

        status = ta.verify_registration(R_reg_MR_fstar_T3)
        if status == "S":
            print("Reg Done SUCCESS for Veh")
            row = [listToString(fx_list), VID, VPR, listToString(f_w_i), listToString(f_star_w_2i), veh_comp_time,"1.0.0"]
            if PYEXCEL_AVAILABLE:
                try:
                    sheet = pe.get_sheet(file_name=save_path_veh)
                    sheet.row += row
                    sheet.save_as(save_path_veh)
                except Exception:
                    _save_csv("FRI_Veh_Reg.csv", row)
            else:
                _save_csv("FRI_Veh_Reg.csv", row)
        else:
            print("Reg failed")
    else:
        print("T2 check Failed")


def _save_csv(fname, row):
    header_needed = not os.path.exists(fname)
    with open(fname, "a", newline="") as f:
        writer = csv.writer(f)
        if header_needed:
            writer.writerow(["f_coeffs", "VID", "VPR", "f_w_i", "f_star_w_2i", "veh_comp_time11", "veh_comp_time"])
        writer.writerow(row)

def main():
    ta = TrustedAuthority()
    run_manufacturer(ta)


if __name__ == "__main__":
    main()
