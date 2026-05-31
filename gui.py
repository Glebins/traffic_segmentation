import threading
import tkinter as tk
from tkinter import ttk, messagebox
import tkinter.font as tkfont
import csv
import os
import time

LOG_PATH = "flow_log_test.csv"
REFRESH_INTERVAL = 1000  # ms
MAX_ROWS = 150

COLOR_MAP = {
    'CRITICAL': '#ff6b6b',
    'HIGH': '#ff6b6b',
    'WARNING': '#ffeb99',
    'ACCUMULATION': '#dcdcdc',
}
ACCUMULATION_STATE_FILE = 'accumulation_state.txt'
ACCENT_COLOR = '#2b7cff'

class FlowViewer(tk.Tk):
    def __init__(self, log_path=LOG_PATH):
        super().__init__()
        self.title("Traffic Flows Monitor")
        self.geometry("1100x560")
        self.log_path = log_path
        # Apply modern ttk theme and styles
        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        heading_font = tkfont.nametofont("TkHeadingFont")
        heading_font.configure(weight="bold", size=10)
        default_font = tkfont.nametofont("TkTextFont")
        default_font.configure(size=10)

        style.configure("Treeview.Heading", font=heading_font)
        style.configure("Treeview", font=default_font, rowheight=24)

        # Toolbar
        toolbar = ttk.Frame(self)
        toolbar.pack(fill='x', padx=6, pady=6)

        self.refresh_btn = ttk.Button(toolbar, text="Refresh", command=self.refresh)
        self.refresh_btn.pack(side='left')

        ttk.Label(toolbar, text="  Filter:").pack(side='left', padx=(8, 2))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(toolbar, textvariable=self.filter_var, width=30)
        self.filter_entry.pack(side='left')
        self.filter_entry.bind('<KeyRelease>', lambda e: self.refresh())
        # placeholder behaviour
        self.filter_placeholder = 'search by pid/process/status...'
        self.filter_entry.insert(0, self.filter_placeholder)
        self.filter_entry.config(foreground='grey')
        self.filter_entry.bind('<FocusIn>', self._on_filter_focus_in)
        self.filter_entry.bind('<FocusOut>', self._on_filter_focus_out)

        self.train_models_btn = ttk.Button(toolbar, text="Train anomaly models", command=self.start_training)
        self.train_models_btn.pack(side='right', padx=(4, 0))

        self.accumulation_btn = ttk.Button(toolbar, text="", command=self.toggle_accumulation_mode)
        self.accumulation_btn.pack(side='right', padx=(4, 0))

        self.accumulation_state_label = ttk.Label(toolbar, text="", foreground='#555555')
        self.accumulation_state_label.pack(side='right', padx=(0, 10))

        self.update_accumulation_button()

        # Header / accent bar
        header = ttk.Frame(self)
        header.pack(fill='x')
        accent = tk.Frame(header, bg=ACCENT_COLOR, height=6)
        accent.pack(fill='x')
        title_frame = ttk.Frame(header)
        title_frame.pack(fill='x', padx=8, pady=(8, 0))
        ttk.Label(title_frame, text='Traffic Flows Monitor', font=(None, 14, 'bold')).pack(side='left')
        ttk.Label(title_frame, text='  — Live viewer', foreground='#666666').pack(side='left')

        # Treeview
        self.columns = ("ts","PID","process","num_of_packets","threat probability","status","xgb_score","xgb_label","anomaly_score")
        self.tree = ttk.Treeview(self, columns=self.columns, show='headings')
        for col, width in [("ts",160),("PID",60),("process",220),("num_of_packets",100),("threat probability",120),("status",220),("xgb_score",100),("xgb_label",120),("anomaly_score",100)]:
            # attach sort command to heading
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_tree(c, False))
            self.tree.column(col, width=width, anchor='w')
        self.tree.pack(fill='both', expand=True, padx=6, pady=(0,6))
        self.tree.bind('<Double-1>', self.on_double)
        self.tree.bind('<Button-3>', self.on_right_click)


        self.statusbar = ttk.Label(self, text="Ready")
        self.statusbar.pack(fill='x')

        # Setup tag styles for coloring
        style = ttk.Style(self)

        # Tag styles
        self.tree.tag_configure('red', background=COLOR_MAP['CRITICAL'])
        self.tree.tag_configure('yellow', background=COLOR_MAP['WARNING'])
        self.tree.tag_configure('accumulation', background=COLOR_MAP['ACCUMULATION'])
        self.tree.tag_configure('odd', background='#fbfbfb')
        self.tree.tag_configure('even', background='#ffffff')

        self.after(200, self.refresh)

    def refresh(self):
        rows = self.read_last_rows(MAX_ROWS)
        self.tree.delete(*self.tree.get_children())
        filter_text = (self.filter_var.get() or '').strip().lower()
        # Treat placeholder as empty filter so initial load shows rows
        try:
            if filter_text == getattr(self, 'filter_placeholder', '').lower():
                filter_text = ''
        except Exception:
            pass
        visible_count = 0
        for idx, r in enumerate(rows):
            ts = r.get('ts','').split()[1]
            pid = r.get('PID','')
            proc = r.get('process','')
            num_p = r.get('num_of_packets','')
            threat_prob = r.get('threat probability','')
            status = r.get('status','')
            xgb_score = r.get('xgb_score','')
            xgb_label = r.get('xgb_label','')
            anomaly = r.get('anomaly_score','')

            line_text = f"{ts} {pid} {proc} {status} {xgb_label}"
            if filter_text and filter_text not in line_text.lower():
                continue

            iid = self.tree.insert('','end', values=(ts,pid,proc,num_p,threat_prob,status,xgb_score,xgb_label,anomaly))
            # Color based on status and alternating rows
            tags = []
            if idx % 2 == 0:
                tags.append('even')
            else:
                tags.append('odd')

            if status:
                st = status.upper()
                if 'ACCUMULATION' in st:
                    tags.append('accumulation')
                elif 'CRITICAL' in st or 'HIGH' in st:
                    tags.append('red')
                elif 'WARNING' in st:
                    tags.append('yellow')

            if tags:
                self.tree.item(iid, tags=tuple(tags))
            visible_count += 1

        # Autosize columns to content
        self.autosize_columns()

        # Configure tag styles (do after insert)
        self.tree.tag_configure('red', background=COLOR_MAP['CRITICAL'])
        self.tree.tag_configure('yellow', background=COLOR_MAP['WARNING'])

        # update statusbar with counts
        self.statusbar.config(text=f"Visible: {visible_count}  •  Last update: {time.strftime('%H:%M:%S', time.gmtime())}")
        self.after(REFRESH_INTERVAL, self.refresh)

    def read_last_rows(self, n):
        if not os.path.exists(self.log_path):
            return []
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            return rows[-n:]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read log file: {e}")
            return []

    def autosize_columns(self):
        try:
            font = tkfont.nametofont("TkTextFont")
            for col in self.tree['columns']:
                max_width = 40
                # header
                hdr = col
                w = font.measure(hdr) + 20
                if w > max_width:
                    max_width = w
                for iid in self.tree.get_children():
                    val = str(self.tree.set(iid, col) or '')
                    w = font.measure(val) + 20
                    if w > max_width:
                        max_width = w
                self.tree.column(col, width=min(max_width, 500))
        except Exception:
            pass

    def sort_tree(self, col, reverse=False):
        # Get all items and sort by column value
        try:
            l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
            # try numeric sort
            try:
                l.sort(key=lambda t: float(t[0]) if t[0] != '' else float('-inf'), reverse=reverse)
            except Exception:
                l.sort(key=lambda t: t[0].lower() if isinstance(t[0], str) else t[0], reverse=reverse)
            # rearrange
            for index, (_, k) in enumerate(l):
                self.tree.move(k, '', index)
            # reverse next time
            self.tree.heading(col, command=lambda: self.sort_tree(col, not reverse))
        except Exception:
            pass

    def _on_filter_focus_in(self, event):
        if self.filter_entry.get() == self.filter_placeholder:
            self.filter_entry.delete(0, 'end')
            self.filter_entry.config(foreground='black')

    def _on_filter_focus_out(self, event):
        if not self.filter_entry.get():
            self.filter_entry.insert(0, self.filter_placeholder)
            self.filter_entry.config(foreground='grey')

    def read_accumulation_state(self):
        try:
            if os.path.exists(ACCUMULATION_STATE_FILE):
                with open(ACCUMULATION_STATE_FILE, 'r', encoding='utf-8') as sf:
                    return sf.read().strip().lower() == 'on'
        except Exception:
            pass
        return False

    def write_accumulation_state(self, enabled):
        try:
            with open(ACCUMULATION_STATE_FILE, 'w', encoding='utf-8') as sf:
                sf.write('on' if enabled else 'off')
        except Exception:
            pass

    def update_accumulation_button(self):
        self.accumulation_enabled = self.read_accumulation_state()
        if self.accumulation_enabled:
            self.accumulation_btn.config(text='Stop data accumulation')
            self.accumulation_state_label.config(text='Accumulation mode: ON')
        else:
            self.accumulation_btn.config(text='Start data accumulation')
            self.accumulation_state_label.config(text='Accumulation mode: OFF')

    def toggle_accumulation_mode(self):
        self.accumulation_enabled = not self.read_accumulation_state()
        self.write_accumulation_state(self.accumulation_enabled)
        self.update_accumulation_button()

    def start_training(self):
        self.train_models_btn.config(state='disabled')
        self.train_models_btn.config(text='Training...')
        threading.Thread(target=self.train_models_thread, daemon=True).start()

    def train_models_thread(self):
        errors = []
        try:
            import unsupervised
            unsupervised.train_model()
        except Exception as e:
            errors.append(f"Autoencoder: {e}")
        try:
            import unsupervised_if
            unsupervised_if.train_isolation_forest()
        except Exception as e:
            errors.append(f"Isolation Forest: {e}")
        try:
            import unsupervised_lof
            unsupervised_lof.train_lof()
        except Exception as e:
            errors.append(f"LOF: {e}")

        def finish():
            self.train_models_btn.config(state='normal')
            self.train_models_btn.config(text='Train anomaly models')
            if errors:
                messagebox.showerror('Training finished with errors', '\n'.join(errors))
            else:
                messagebox.showinfo('Training complete', 'Anomaly models were trained successfully.')
        self.after(0, finish)

    # export removed — viewer intentionally read-only

    def on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label='Details', command=lambda: self.show_details(iid))
        menu.add_command(label='Copy row', command=lambda: self.copy_row(iid))
        # export removed from context menu
        menu.tk_popup(event.x_root, event.y_root)

    def show_details(self, iid):
        vals = [self.tree.set(iid, c) for c in self.tree['columns']]
        txt = '\n'.join(f"{col}: {v}" for col, v in zip(self.tree['columns'], vals))
        messagebox.showinfo('Flow details', txt)

    def copy_row(self, iid):
        vals = [self.tree.set(iid, c) for c in self.tree['columns']]
        txt = ','.join(vals)
        self.clipboard_clear()
        self.clipboard_append(txt)

    def on_double(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], 'values')
        # column order: ts, PID, process, num_of_packets, threat probability, status, xgb_score, xgb_label, anomaly_score
        txt = (
            f"Timestamp: {vals[0]}\nPID: {vals[1]}\nProcess: {vals[2]}\n"
            f"Num of packets: {vals[3]}\nThreat probability: {vals[4]}\nStatus: {vals[5]}\n"
            f"XGB score: {vals[6]}\nXGB label: {vals[7]}\nAnomaly score: {vals[8]}"
        )
        messagebox.showinfo("Flow details", txt)

if __name__ == '__main__':
    app = FlowViewer()
    app.mainloop()
