from typing import Dict, List, Optional
from pydantic import BaseModel

class timesOfTime(BaseModel):
    # From /register
    wallet_gen_time: Optional[float] = 0
    wallet_enc_time: Optional[float] = 0
    network_info_time: Optional[float] = 0
    # From /poll
    smt_local_add_time: Optional[float] = 0
    vc_issuance_time: Optional[float] = 0
    smt_onchain_add_time: Optional[float] = 0
    # From /verify
    vp_gen_time: Optional[float] = 0 # From Client
    client_register_total_time: Optional[float] = 0 # From Client, add after meeting
    vp_verify_time: Optional[float] = 0
    vc_verify_time: Optional[float] = 0
    smt_local_verify_time: Optional[float] = 0
    smt_onchain_verify_time: Optional[float] = 0
    smt_proof_gen_time: Optional[float] = 0
    smt_on_server_verify_time: Optional[float] = 0
    # To /update-metrics
    smt_total_verify_time: Optional[float] = 0
    