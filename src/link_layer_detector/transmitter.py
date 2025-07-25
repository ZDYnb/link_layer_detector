from tx_python.Modules.link_layer import packet_gen
from tx_python.Modules.helpers import hex2bin, whiten_fullPacket
from tx_python.Modules.link_layer.ble_packet_decode import packet_decode
from tx_python.Modules.progressbar import printProgressBar
from tx_python.Modules.ble_hardware import AD2Transmitter, PlutoTransmitter
import tkinter as tk
from tkinter import ttk
from threading import Thread
import io
import contextlib

class TransmitterGUI:
    # Default GAP templates
    DEFAULT_NONCONNECTING_GAP = [
        ('FLAGS', '02'),
        ('COMPLETE_LOCAL_NAME', 'SCUM3')
    ]
    DEFAULT_CONNECTING_ADV_IND_GAP = [
        ('FLAGS', '02'),
        ('MANUFACTURER_SPECIFIC_DATA', 'b704de7ec7ab1e7e57ca5e')
    ]
    DEFAULT_CONNECTING_SCAN_RSP_GAP = [
        ('COMPLETE_LOCAL_NAME', 'SCUM3')
    ]

    def __init__(self, master):
        self.master = master
        master.title("BLE Transmitter Control")

        # Main Frame
        main_frame = ttk.Frame(master)
        main_frame.pack(fill="both", expand=True)

        # Left Frame (parameters, GAP, buttons)
        left_frame = ttk.Frame(main_frame)
        left_frame.grid(row=0, column=0, sticky="nsw", padx=8, pady=8)

        # Right Frame (Packet Info)
        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=8, pady=8)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)

        # === NEW: Preset Examples Section ===
        preset_frame = ttk.LabelFrame(left_frame, text="Preset Examples")
        preset_frame.pack(fill="x", pady=2)
        
        ttk.Button(preset_frame, text="Preset ADV_IND Only", 
                  command=self.preset_adv_ind_only).pack(side="left", expand=True, fill="x", padx=2)
        ttk.Button(preset_frame, text="Preset SCAN_RSP Only", 
                  command=self.preset_scan_rsp_only).pack(side="left", expand=True, fill="x", padx=2)
        ttk.Button(preset_frame, text="Preset Connecting Mode", 
                  command=self.preset_connecting_mode).pack(side="left", expand=True, fill="x", padx=2)

        # Parameters section
        param_frame = ttk.LabelFrame(left_frame, text="Parameters")
        param_frame.pack(fill="x", pady=2)

        self.tx_mode = tk.StringVar(value="Non-Connecting")
        ttk.Label(param_frame, text="TX Mode:").grid(row=0, column=0, sticky="w")
        ttk.Combobox(param_frame, textvariable=self.tx_mode, values=["Non-Connecting", "Connecting"], width=16).grid(row=0, column=1, sticky="w")
        self.sdr_ip = tk.StringVar(value="192.168.2.1")
        ttk.Label(param_frame, text="SDR IP:").grid(row=0, column=2, sticky="e")
        ttk.Entry(param_frame, textvariable=self.sdr_ip, width=15).grid(row=0, column=3, sticky="w")

        self.sdr_type = tk.StringVar(value="Pluto")
        self.channel = tk.IntVar(value=37)
        self.freq = tk.DoubleVar(value=2.402e9)
        self.symbol_time = tk.DoubleVar(value=1e-6)
        self.bt = tk.DoubleVar(value=0.5)
        self.tx_power = tk.IntVar(value=-10)
        self.status = tk.StringVar(value="Idle")
        self.packet_str = tk.StringVar(value="")
        self.packet_info = tk.StringVar(value="")
        self.stop_flag = {"stop": False}
        self.tx_thread = None

        ttk.Label(param_frame, text="SDR Type:").grid(row=1, column=0, sticky="w")
        ttk.Combobox(param_frame, textvariable=self.sdr_type, values=["Pluto", "AD2"], width=16).grid(row=1, column=1, sticky="w")
        ttk.Label(param_frame, text="Channel:").grid(row=1, column=2, sticky="e")
        ttk.Entry(param_frame, textvariable=self.channel, width=8).grid(row=1, column=3, sticky="w")

        ttk.Label(param_frame, text="Frequency (Hz):").grid(row=2, column=0, sticky="w")
        ttk.Entry(param_frame, textvariable=self.freq, width=16).grid(row=2, column=1, sticky="w")
        ttk.Label(param_frame, text="Symbol Time (s):").grid(row=2, column=2, sticky="e")
        ttk.Entry(param_frame, textvariable=self.symbol_time, width=8).grid(row=2, column=3, sticky="w")

        ttk.Label(param_frame, text="BT:").grid(row=3, column=0, sticky="w")
        ttk.Entry(param_frame, textvariable=self.bt, width=16).grid(row=3, column=1, sticky="w")
        ttk.Label(param_frame, text="TX Power (dBm):").grid(row=3, column=2, sticky="e")
        ttk.Entry(param_frame, textvariable=self.tx_power, width=8).grid(row=3, column=3, sticky="w")

        self.pdu_types = [
            'ADV_IND', 'ADV_DIRECT_IND', 'ADV_NONCONN_IND',
            'SCAN_REQ', 'SCAN_RSP', 'CONNECT_REQ', 'ADV_SCAN_IND'
        ]
        self.pdu_type = tk.StringVar(value=self.pdu_types[0])
        ttk.Label(param_frame, text="PDU Type:").grid(row=4, column=0, sticky="w")
        self.pdu_type_cb = ttk.Combobox(param_frame, textvariable=self.pdu_type, values=self.pdu_types, width=16)
        self.pdu_type_cb.grid(row=4, column=1, sticky="w")
        ttk.Label(param_frame, text="Status:").grid(row=4, column=2, sticky="e")
        ttk.Label(param_frame, textvariable=self.status, width=12).grid(row=4, column=3, sticky="w")

        # Padding controls and time display (μs)
        self.reset_time_val = tk.DoubleVar(value=0.0)
        self.interval_time_val = tk.DoubleVar(value=0.0)
        self.reset_padding_len = tk.IntVar(value=48)
        self.interval_padding_len = tk.IntVar(value=64)
        padding_frame = ttk.LabelFrame(left_frame, text="Padding Controls")
        padding_frame.pack(fill="x", pady=2)

        ttk.Label(padding_frame, text="Reset Time (μs):").grid(row=0, column=0, sticky="w")
        reset_time_entry = ttk.Entry(padding_frame, textvariable=self.reset_time_val, width=10)
        reset_time_entry.grid(row=0, column=1, sticky="w")
        ttk.Label(padding_frame, text="→ Padding (hex zeros):").grid(row=0, column=2, sticky="w")
        reset_pad_entry = ttk.Entry(padding_frame, textvariable=self.reset_padding_len, width=10)
        reset_pad_entry.grid(row=0, column=3, sticky="w")

        ttk.Label(padding_frame, text="Interval Time (μs):").grid(row=1, column=0, sticky="w")
        interval_time_entry = ttk.Entry(padding_frame, textvariable=self.interval_time_val, width=10)
        interval_time_entry.grid(row=1, column=1, sticky="w")
        ttk.Label(padding_frame, text="→ Padding (hex zeros):").grid(row=1, column=2, sticky="w")
        interval_pad_entry = ttk.Entry(padding_frame, textvariable=self.interval_padding_len, width=10)
        interval_pad_entry.grid(row=1, column=3, sticky="w")

        self.reset_time_val.trace_add("write", self.update_padding_from_time)
        self.interval_time_val.trace_add("write", self.update_padding_from_time)

        # Dynamic GAP block section for Non-Connecting
        self.gap_types = [
            'FLAGS',
            '128BIT_SERVICE_UUID_COMPLETE',
            'SHORT_LOCAL_NAME',
            'COMPLETE_LOCAL_NAME',
            'MANUFACTURER_SPECIFIC_DATA',
            'INCOMPLETE_LIST_16BIT_SERVICE_UUIDS',
            'SERVICE_DATA',
            '16BIT_SERVICE_UUID_COMPLETE'
        ]
        self.gap_blocks = []
        self.gap_frame = ttk.LabelFrame(left_frame, text="GAP Blocks")
        # Use default template for Non-Connecting
        for gap_type, gap_value in self.DEFAULT_NONCONNECTING_GAP:
            self.add_gap_block_row(initial_type=gap_type, initial_value=gap_value)
        self.add_gap_btn = ttk.Button(left_frame, text="Add GAP Block", command=self.add_gap_block_row)

        # ADV_IND and SCAN_RSP GAP blocks for Connecting mode
        self.advind_gap_blocks = []
        self.advind_gap_frame = ttk.LabelFrame(left_frame, text="ADV_IND GAP Blocks")
        for gap_type, gap_value in self.DEFAULT_CONNECTING_ADV_IND_GAP:
            self.add_gap_block_row(self.advind_gap_blocks, self.advind_gap_frame, gap_type, gap_value)
        self.add_advind_gap_btn = ttk.Button(left_frame, text="Add ADV_IND GAP Block",
                                             command=lambda: self.add_gap_block_row(self.advind_gap_blocks, self.advind_gap_frame))

        self.scanrsp_gap_blocks = []
        self.scanrsp_gap_frame = ttk.LabelFrame(left_frame, text="SCAN_RSP GAP Blocks")
        for gap_type, gap_value in self.DEFAULT_CONNECTING_SCAN_RSP_GAP:
            self.add_gap_block_row(self.scanrsp_gap_blocks, self.scanrsp_gap_frame, gap_type, gap_value)
        self.add_scanrsp_gap_btn = ttk.Button(left_frame, text="Add SCAN_RSP GAP Block",
                                              command=lambda: self.add_gap_block_row(self.scanrsp_gap_blocks, self.scanrsp_gap_frame))

        # Control buttons
        btn_frame = ttk.Frame(left_frame)
        self.start_btn = ttk.Button(btn_frame, text="Start", command=self.start_tx)
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_tx, state=tk.DISABLED)
        self.restart_btn = ttk.Button(btn_frame, text="Restart", command=self.restart_tx, state=tk.DISABLED)
        self.start_btn.pack(side="left", expand=True, fill="x", padx=2)
        self.stop_btn.pack(side="left", expand=True, fill="x", padx=2)
        self.restart_btn.pack(side="left", expand=True, fill="x", padx=2)
        btn_frame.pack(fill="x", pady=8)

        # GAP Block layout
        self.gap_frame.pack(fill="x", pady=2)
        self.add_gap_btn.pack(fill="x", pady=2)
        self.advind_gap_frame.pack(fill="x", pady=2)
        self.add_advind_gap_btn.pack(fill="x", pady=2)
        self.scanrsp_gap_frame.pack(fill="x", pady=2)
        self.add_scanrsp_gap_btn.pack(fill="x", pady=2)

        # Packet Info (right)
        info_frame = ttk.LabelFrame(right_frame, text="Packet Info")
        info_frame.pack(fill="both", expand=True)
        self.packet_info_text = tk.Text(info_frame, width=70, height=30, wrap="word")
        self.packet_info_text.pack(fill="both", expand=True)
        self.packet_info.trace_add("write", self.update_packet_info_text)

        # Show/hide GAP block frames based on mode
        self.tx_mode.trace_add("write", self.update_gap_block_visibility)
        self.update_gap_block_visibility()

    # === NEW: Preset Configuration Methods ===
    def preset_adv_ind_only(self):
        """Configure for ADV_IND only transmission"""
        # Set mode to Non-Connecting
        self.tx_mode.set("Non-Connecting")
        
        # Set PDU type to ADV_IND
        self.pdu_type.set("ADV_IND")
        
        # Clear existing GAP blocks and set preset ADV_IND GAP data
        self.clear_gap_blocks(self.gap_blocks, self.gap_frame)
        for gap_type, gap_value in self.DEFAULT_CONNECTING_ADV_IND_GAP:
            self.add_gap_block_row(initial_type=gap_type, initial_value=gap_value)
        
        # Set timing for single packet (no interval needed)
        self.reset_time_val.set(100.0)  # 100μs reset time
        self.interval_time_val.set(0.0)   # No interval for single packet
        
        # Update packet info
        self.packet_info.set("PRESET: ADV_IND Only Mode Configured\nClick 'Start' to transmit ADV_IND packets only.")

    def preset_scan_rsp_only(self):
        """Configure for SCAN_RSP only transmission"""
        # Set mode to Non-Connecting
        self.tx_mode.set("Non-Connecting")
        
        # Set PDU type to SCAN_RSP
        self.pdu_type.set("SCAN_RSP")
        
        # Clear existing GAP blocks and set preset SCAN_RSP GAP data
        self.clear_gap_blocks(self.gap_blocks, self.gap_frame)
        for gap_type, gap_value in self.DEFAULT_CONNECTING_SCAN_RSP_GAP:
            self.add_gap_block_row(initial_type=gap_type, initial_value=gap_value)
        
        # Set timing for single packet (no interval needed)
        self.reset_time_val.set(100.0)  # 100μs reset time
        self.interval_time_val.set(0.0)   # No interval for single packet
        
        # Update packet info
        self.packet_info.set("PRESET: SCAN_RSP Only Mode Configured\nClick 'Start' to transmit SCAN_RSP packets only.")

    def preset_connecting_mode(self):
        """Configure for Connecting mode with both ADV_IND and SCAN_RSP"""
        # Set mode to Connecting
        self.tx_mode.set("Connecting")
        
        # Clear and set ADV_IND GAP blocks
        self.clear_gap_blocks(self.advind_gap_blocks, self.advind_gap_frame)
        for gap_type, gap_value in self.DEFAULT_CONNECTING_ADV_IND_GAP:
            self.add_gap_block_row(self.advind_gap_blocks, self.advind_gap_frame, gap_type, gap_value)
        
        # Clear and set SCAN_RSP GAP blocks
        self.clear_gap_blocks(self.scanrsp_gap_blocks, self.scanrsp_gap_frame)
        for gap_type, gap_value in self.DEFAULT_CONNECTING_SCAN_RSP_GAP:
            self.add_gap_block_row(self.scanrsp_gap_blocks, self.scanrsp_gap_frame, gap_type, gap_value)
        
        # Set timing for connecting mode (reset + interval between packets)
        self.reset_time_val.set(468)   # 100μs reset time
        self.interval_time_val.set(480) # 250μs interval between ADV_IND and SCAN_RSP
        
        # Update packet info
        self.packet_info.set("PRESET: Connecting Mode Configured\nADV_IND and SCAN_RSP will be transmitted with 250μs interval.\nClick 'Start' to begin transmission.")

    def clear_gap_blocks(self, block_list, frame):
        """Helper method to clear all GAP blocks from a frame"""
        for type_var, value_var, *widgets in block_list[:]:
            for widget in widgets:
                widget.grid_forget()
        block_list.clear()

    def update_padding_from_time(self, *args):
        try:
            symbol_time = float(self.symbol_time.get())
            reset_len = int(round(self.reset_time_val.get() / (4 * symbol_time * 1e6)))
            interval_len = int(round(self.interval_time_val.get() / (4 * symbol_time * 1e6)))
            self.reset_padding_len.set(reset_len)
            self.interval_padding_len.set(interval_len)
        except Exception:
            pass

    def update_packet_info_text(self, *args):
        self.packet_info_text.delete("1.0", tk.END)
        self.packet_info_text.insert(tk.END, self.packet_info.get())

    def update_gap_block_visibility(self, *args):
        if self.tx_mode.get() == "Non-Connecting":
            self.gap_frame.pack(fill="x", pady=2)
            self.add_gap_btn.pack(fill="x", pady=2)
            self.advind_gap_frame.pack_forget()
            self.add_advind_gap_btn.pack_forget()
            self.scanrsp_gap_frame.pack_forget()
            self.add_scanrsp_gap_btn.pack_forget()
        else:
            self.gap_frame.pack_forget()
            self.add_gap_btn.pack_forget()
            self.advind_gap_frame.pack(fill="x", pady=2)
            self.add_advind_gap_btn.pack(fill="x", pady=2)
            self.scanrsp_gap_frame.pack(fill="x", pady=2)
            self.add_scanrsp_gap_btn.pack(fill="x", pady=2)

    def add_gap_block_row(self, block_list=None, frame=None, initial_type=None, initial_value=None):
        if block_list is None:
            block_list = self.gap_blocks
        if frame is None:
            frame = self.gap_frame
        row = len(block_list)
        type_var = tk.StringVar(value=initial_type if initial_type else self.gap_types[0])
        value_var = tk.StringVar(value=initial_value if initial_value else "")
        type_cb = ttk.Combobox(frame, textvariable=type_var, values=self.gap_types, width=30)
        value_entry = ttk.Entry(frame, textvariable=value_var, width=30)
        type_cb.grid(row=row, column=0, padx=2, pady=2)
        value_entry.grid(row=row, column=1, padx=2, pady=2)
        remove_btn = ttk.Button(frame, text="Remove", command=lambda: self.remove_gap_block_row(row, block_list, frame))
        remove_btn.grid(row=row, column=2, padx=2, pady=2)
        block_list.append((type_var, value_var, type_cb, value_entry, remove_btn))

    def remove_gap_block_row(self, idx, block_list=None, frame=None):
        if block_list is None:
            block_list = self.gap_blocks
        if frame is None:
            frame = self.gap_frame
        for widget in block_list[idx][2:]:
            widget.grid_forget()
        block_list.pop(idx)
        # Repack remaining rows
        for i, (type_var, value_var, type_cb, value_entry, remove_btn) in enumerate(block_list):
            type_cb.grid(row=i, column=0, padx=2, pady=2)
            value_entry.grid(row=i, column=1, padx=2, pady=2)
            remove_btn.grid(row=i, column=2, padx=2, pady=2)

    def start_tx(self):
        self.status.set("Connecting...")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.restart_btn.config(state=tk.NORMAL)
        self.stop_flag["stop"] = False

        ch = self.channel.get()
        freq = self.freq.get()
        symbol_time = self.symbol_time.get()
        bt = self.bt.get()
        tx_power = self.tx_power.get()
        adv_type = self.pdu_type.get()
        sdr_ip = self.sdr_ip.get()

        info = ""
        # Padding controls
        reset_padding = "0" * self.reset_padding_len.get()
        interval_padding = "0" * self.interval_padding_len.get()

        if self.tx_mode.get() == "Non-Connecting":
            # Collect GAP blocks from the GUI
            gap_data = []
            for type_var, value_var, *_ in self.gap_blocks:
                gap_type = type_var.get()
                gap_value = value_var.get()
                if gap_type and gap_value:
                    gap_data.append([gap_type, gap_value])
            ble_packet = packet_gen('8e89bed6', adv_type, '90d7ebb19299', gap_data)
            whitened_packet = whiten_fullPacket(ble_packet, ch)
            full_packet_hex = reset_padding + whitened_packet + interval_padding
            packet = hex2bin(full_packet_hex)

            # Capture verbose decode output for info display
            f = io.StringIO()
            try:
                with contextlib.redirect_stdout(f):
                    packet_decode(whitened_packet, verbose=True)
                decoded_verbose = f.getvalue()
            except Exception as e:
                decoded_verbose = f"Decode error: {e}"

            info = (
                f"Full BLE Packet:\n0x{ble_packet}\n({len(ble_packet)//2} bytes)\n"
                f"Whitened Packet:\n0x{whitened_packet}\n({len(whitened_packet)//2} bytes)\n"
            )
        else:
            # ADV_IND
            advind_gap_data = []
            for type_var, value_var, *_ in self.advind_gap_blocks:
                gap_type = type_var.get()
                gap_value = value_var.get()
                if gap_type and gap_value:
                    advind_gap_data.append([gap_type, gap_value])
            advind_ble_packet = packet_gen('8e89bed6', "ADV_IND", '90d7ebb19299', advind_gap_data)
            advind_whitened_packet = whiten_fullPacket(advind_ble_packet, ch)

            # SCAN_RSP
            scanrsp_gap_data = []
            for type_var, value_var, *_ in self.scanrsp_gap_blocks:
                gap_type = type_var.get()
                gap_value = value_var.get()
                if gap_type and gap_value:
                    scanrsp_gap_data.append([gap_type, gap_value])
            scanrsp_ble_packet = packet_gen('8e89bed6', "SCAN_RSP", '90d7ebb19299', scanrsp_gap_data)
            scanrsp_whitened_packet = whiten_fullPacket(scanrsp_ble_packet, ch)

            # Show info for both packets
            f1 = io.StringIO()
            try:
                with contextlib.redirect_stdout(f1):
                    packet_decode(advind_whitened_packet, verbose=True)
                advind_decoded_verbose = f1.getvalue()
            except Exception as e:
                advind_decoded_verbose = f"Decode error: {e}"

            f2 = io.StringIO()
            try:
                with contextlib.redirect_stdout(f2):
                    packet_decode(scanrsp_whitened_packet, verbose=True)
                scanrsp_decoded_verbose = f2.getvalue()
            except Exception as e:
                scanrsp_decoded_verbose = f"Decode error: {e}"

            info = (
                f"ADV_IND BLE Packet:\n0x{advind_ble_packet}\n({len(advind_ble_packet)//2} bytes)\n"
                f"Whitened Packet:\n0x{advind_whitened_packet}\n({len(advind_whitened_packet)//2} bytes)\n"
                # f"Decoded Info:\n{advind_decoded_verbose}\n"
                f"---\n"
                f"SCAN_RSP BLE Packet:\n0x{scanrsp_ble_packet}\n({len(scanrsp_ble_packet)//2} bytes)\n"
                f"Whitened Packet:\n0x{scanrsp_whitened_packet}\n({len(scanrsp_whitened_packet)//2} bytes)\n"
            )

            full_packet_hex = reset_padding + advind_whitened_packet + interval_padding + scanrsp_whitened_packet
            packet = hex2bin(full_packet_hex)

        # Convert binary string to bytes for display
        binary_packet_bytes = int(packet, 2).to_bytes((len(packet) + 7) // 8, byteorder='big')
        binary_packet_hex = binary_packet_bytes.hex()

        # Calculate time intervals for paddings (rounded, μs)
        symbol_time_val = self.symbol_time.get()
        reset_time_us = round(self.reset_padding_len.get() * 4 * symbol_time_val * 1e6)
        interval_time_us = round(self.interval_padding_len.get() * 4 * symbol_time_val * 1e6)

        # Format the transmission info nicely
        transmission_mode = "Single Packet" if self.tx_mode.get() == "Non-Connecting" else "Dual Packet (ADV_IND + SCAN_RSP)"
        
        info += (
            f"\n" + "="*60 + "\n"
            f"Reset Time:    {reset_time_us:>6} μs  →  {self.reset_padding_len.get():>3} hex zeros padding\n"
            f"Interval Time: {interval_time_us:>6} μs  →  {self.interval_padding_len.get():>3} hex zeros padding\n"
            f"\n"
            f"Mode:          {transmission_mode}\n"
            f"Target IP:     {sdr_ip}\n"
            f"Frequency:     {freq/1e9:.3f} GHz (Channel {ch})\n"
            f"TX Power:      {tx_power} dBm\n"
            f"\n Final Binary Packet (continuously transmitted):\n"
            f"0x{binary_packet_hex}\n"
            f"Length:        {len(binary_packet_bytes)} bytes\n"
            f"\n INFO: This packet is sent to {self.sdr_type.get()} SDR and transmitted\n"
            f"    continuously in a loop until 'Stop' is pressed.\n"
            f"    The packet includes reset padding + BLE data + interval padding."
        )
        self.packet_info.set(info)

        self.tx_thread = Thread(target=run_transmitter, args=(
            self.sdr_type.get(), freq, symbol_time, bt, tx_power, packet, self.stop_flag, self.status.set, sdr_ip
        ), daemon=True)
        self.tx_thread.start()

    def stop_tx(self):
        self.status.set("Stopped")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.restart_btn.config(state=tk.DISABLED)
        self.stop_flag["stop"] = True

    def restart_tx(self):
        self.stop_tx()
        self.master.after(500, self.start_tx)

def run_transmitter(sdr_type, freq, symbol_time, bt, tx_power, packet, stop_flag, status_callback, sdr_ip):
    try:
        if sdr_type == "Pluto":
            sdr = PlutoTransmitter(freq, symbol_time, bt, tx_power, 0, sdr=f'ip:{sdr_ip}')
            sdr.set_sample_rate()
        else:
            sdr = AD2Transmitter(freq, symbol_time, bt, tx_power)
        sdr.set_tx_freq(freq)
        sdr.set_packet(packet)
        status_callback("Connected, Transmitting...")
        sdr.repeating_transmit()
        while not stop_flag["stop"]:
            pass
        sdr.close()
        status_callback("Stopped")
    except Exception as e:
        status_callback(f"Error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = TransmitterGUI(root)
    root.mainloop()