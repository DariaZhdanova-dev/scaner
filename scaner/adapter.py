import pandas as pd
import psutil
import numpy as np

from . import check_sign, net, check_pack, capa_scan, pe_analyse, mem_analyse

class ScanerAdapter:
    
    def __init__(self) -> None:
        self._procs = []
        self._paths = []
        self._net = net.NetConnectionCheck()
    
    def get_proc_table(self) -> pd.DataFrame:
        """
        Table format:
        columns (pid, path, net, sign, repr)
        reper is a proc non safety report between 0-100%

        Returns:
            pd.DataFrame: proc table 
        """
        self._scan_procs()
        table = pd.DataFrame({
            "pid": [proc.pid for proc in self._procs]
            })
        table["path"] = self._paths
        table["sign"] = self._proc_signs()
        table["net"] = self._proc_nets()
        table["repr"] = np.logical_and(
            np.logical_not(table["sign"]), 
            table["net"].apply(
                lambda string: "" if string.startswith("GOOD") else string
                ).fillna("") != "")
        return table
    
    def _scan_procs(self) -> None:
        """
        Update proc and path lists

        Returns:
            None
        """
        def _get_path(proc: psutil.Process):
            try:
                return proc.exe()
            except Exception:
                return proc.name()
        
        self._procs = list(psutil.process_iter(['name']))
        self._paths = [_get_path(proc) for proc in self._procs]
        self._net.scan()
        
    def _proc_signs(self) -> list:
        """
        Check procs signatures

        Returns:
            list: signatures for procs
        """
        return [check_sign.check_sign(path)[0] for path in self._paths]
    
    def _proc_nets(self) -> list:
        def _net2srt(conn):
            if conn is None:
                return ""
            
            res = "GOOD IP" if self._net.check_ip(conn) else "BAD IP"
            get_addr = lambda addr: f"{getattr(addr, 'ip', '?')}:{getattr(addr, 'port', '?')}"
            
            return f'{res} {get_addr(conn.laddr)} -> {get_addr(conn.raddr)}'
        
        model = self._net.get_model()
        
        return [_net2srt(model.get(proc.pid)) for proc in self._procs]
    
    def _proc_capa(self, pid: int) -> str:
        capa_msg = capa_scan.scan(pid)[1]
        out = f"""
        CAPA:
    
        {capa_msg.decode()}
        """
        return out
    
    def _proc_pe(self, pid: int) -> str:
        pe = pe_analyse.analyze_pe_file(pid)
        out = f"""
        PE:
        
        {pe}
        """
        return out
    
    def _proc_packer(self, pid: int) -> str:
        packer = check_pack.check_packer(pid)[1]
        out = f"""
        PACKER:
        
        {packer}
        """
        return out
    
    def _proc_memory(self, pid: int) -> str:
        mem = mem_analyse.compare_mem_img(pid)
        out = f"""
        MEMORY:
        
        {mem}
        """
        return out