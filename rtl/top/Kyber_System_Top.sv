`timescale 1ns / 1ps
//-----------------------------------------------------------------------------
// Kyber_System_Top.sv — Top-level integration module
//
// Pipeline: RO_PUF → Fuzzy Extractor → Keccak KDF → Kyber Server
// Control: PC (Server) ↔ UART ↔ FPGA (Client)
//
// Commands:
//   0x01 = ENROLL: Read PUF → Generate Helper Data → Send to PC
//   0x02 = RECONSTRUCT: Receive Helper Data → Recover Key → Run Kyber
//-----------------------------------------------------------------------------

module Kyber_System_Top(
    input  wire CLK100MHZ,
    
    // Use Switch 0 for active-low reset
    input  wire [1:0] SW,
    
    // UART interface to PC
    input  wire UART_RXD,
    output wire UART_TXD,
    
    // Kyber Interface (Internal to avoid IO placement errors on Arty A7)
    // We will use 2 LEDs to output the status
    output wire [1:0] LED
);

    wire clk = CLK100MHZ;
    
    // ==========================================
    // Power-On Reset (POR) — tự động nhả reset sau khi FPGA boot
    // Giữ reset 65536 cycles (~1.31 ms @ 50 MHz), sau đó tự động RUN.
    // SW[0] = 0 (down) sẽ ép reset thủ công bất kỳ lúc nào.
    // ==========================================
    reg [15:0] por_cnt = 0;
    reg        por_done = 0;
    always @(posedge clk) begin
        if (!por_done) begin
            por_cnt  <= por_cnt + 1'b1;
            por_done <= (por_cnt == 16'hFFFF);
        end
    end
    // rst_n = 1 (run) khi POR xong VÀ SW[0] = 1 (hoặc không cần gạt)
    // Nếu muốn chạy tự động mà không cần gạt SW: bỏ "&& SW[0]"
    wire rst_n = por_done; // Auto-run after POR, SW[0] freed for other use
    wire rx = UART_RXD;
    wire tx;
    wire tx_active;
    wire kyber_done;
    wire [263:0] puf_resp;
    wire [191:0] fe_key;
    wire [511:0] kyber_seed;
    assign UART_TXD = tx;

    // Shared Secret Output (Internal)
    (* keep = "true" *) wire [255:0] shared_secret_K;
    
    // LED[0]: UART TX Active
    // LED[1]: Kyber completion status. Never expose a function of secret data.
    assign LED[0] = tx_active;
    assign LED[1] = kyber_done;
    
    wire        hash_grant;
    wire        hash_keccak_init, hash_keccak_init_hard;
    wire [1:0]  hash_keccak_mode;
    wire        hash_keccak_wr_en, hash_keccak_wr_xor, hash_keccak_wr_last;
    wire [31:0] hash_keccak_din;
    wire        hash_keccak_rd_en, hash_keccak_rd_extend;

    wire        kdf_req, kdf_grant;
    wire        kdf_init, kdf_hard_init;
    wire [1:0]  kdf_mode;
    wire        kdf_wr_en, kdf_wr_xor, kdf_wr_last;
    wire [31:0] kdf_din;
    wire        kdf_rd_en, kdf_rd_extend;

    wire        sh_busy, sh_idle, sh_dout_valid, sh_done, sh_done_extend;
    wire [31:0] sh_dout;
    wire [5:0]  sh_dout_rate_words;

    // ==========================================
    // 1. RISC-V SoC Core (PicoRV32 + Firmware + Peripherals)
    // ==========================================
    wire puf_start_r, fe_start_r, fe_mode_r, kdf_start_r;
    wire puf_done, fe_done, fe_success, kdf_done;
    // SoC-FE helper data connections
    wire [263:0] helper_soc_to_fe; // From UART to FE
    wire [263:0] helper_fe_to_soc; // From FE to UART
    
    riscv_soc #(.CLKS_PER_BIT(434)) u_soc (
        .clk(clk),
        .rstn(rst_n),
        .rx(rx),
        .tx(tx),
        .tx_active(tx_active),
        .kyber_done(kyber_done),
        .kyber_shared_secret(shared_secret_K),
        .puf_start(puf_start_r),
        .fe_start(fe_start_r),
        .fe_mode(fe_mode_r),
        .kdf_start(kdf_start_r),
        .puf_done(puf_done),
        .fe_done(fe_done),
        .fe_success(fe_success),
        .kdf_done(kdf_done),
        .helper_out(helper_soc_to_fe),
        .helper_in(helper_fe_to_soc),
        .kdf_seed(kyber_seed),
        .hash_grant              (hash_grant),
        .hash_keccak_init        (hash_keccak_init),
        .hash_keccak_init_hard   (hash_keccak_init_hard),
        .hash_keccak_mode        (hash_keccak_mode),
        .hash_keccak_wr_en       (hash_keccak_wr_en),
        .hash_keccak_din         (hash_keccak_din),
        .hash_keccak_wr_xor      (hash_keccak_wr_xor),
        .hash_keccak_wr_last     (hash_keccak_wr_last),
        .hash_keccak_rd_en       (hash_keccak_rd_en),
        .hash_keccak_rd_extend   (hash_keccak_rd_extend),
        .sh_busy                 (sh_busy),
        .sh_idle                 (sh_idle),
        .sh_dout                 (sh_dout),
        .sh_dout_valid           (sh_dout_valid),
        .sh_done                 (sh_done),
        .sh_done_extend          (sh_done_extend),
        .sh_dout_rate_words      (sh_dout_rate_words)
    );

    // ==========================================
    // 4. RO PUF Module
    // ==========================================
    kp_puf_top u_puf (
        .clk(clk),
        .rst_n(rst_n),
        .start(puf_start_r),
        .seed(8'h42),
        .busy(),
        .done(puf_done),
        .response(puf_resp)
    );

    // ==========================================
    // 5. Fuzzy Extractor (BCH)
    // ==========================================
    fuzzy_extractor u_fe (
        .clk(clk),
        .rst_n(rst_n),
        .start(fe_start_r),
        .mode(fe_mode_r),
        .response_in(puf_resp),
        .helper_in(helper_soc_to_fe),
        .helper_out(helper_fe_to_soc),
        .key_out(fe_key),
        .busy(),
        .done(fe_done),
        .success(fe_success)
    );

    // ==========================================
    // 6. Keccak KDF (192-bit -> 512-bit)
    // ==========================================
    kdf_keccak u_kdf (
        .clk(clk),
        .rst_n(rst_n),
        .start(kdf_start_r),
        .key_in(fe_key),
        .done(kdf_done),
        .seed_out(kyber_seed),
        // NEW: shared Keccak bus (client 1)
        .kdf_req       (kdf_req),
        .kdf_grant     (kdf_grant),
        .kdf_init      (kdf_init),
        .kdf_hard_init (kdf_hard_init),
        .kdf_mode      (kdf_mode),
        .kdf_wr_en     (kdf_wr_en),
        .kdf_din       (kdf_din),
        .kdf_wr_xor    (kdf_wr_xor),
        .kdf_wr_last   (kdf_wr_last),
        .kdf_rd_en     (kdf_rd_en),
        .kdf_rd_extend (kdf_rd_extend),
        .sh_done       (sh_done),
        .sh_dout_valid (sh_dout_valid),
        .sh_dout       (sh_dout)
    );
    
    // ==========================================
    // 7. Shared Keccak core: hash_core_Server (via riscv_soc/Kyber_Server)
    //    + kdf_keccak, arbitrated onto ONE sha3_shake_core
    // ==========================================
    keccak_shared_arbiter u_keccak_shared (
        .clk                 (clk),
        .rst                 (~rst_n),   // arbiter/hash_core use active-high rst

        .hash_init           (hash_keccak_init),
        .hash_hard_init      (hash_keccak_init_hard),
        .hash_mode           (hash_keccak_mode),
        .hash_wr_en          (hash_keccak_wr_en),
        .hash_din            (hash_keccak_din),
        .hash_wr_xor         (hash_keccak_wr_xor),
        .hash_wr_last        (hash_keccak_wr_last),
        .hash_rd_en          (hash_keccak_rd_en),
        .hash_rd_extend      (hash_keccak_rd_extend),

        .kdf_req             (kdf_req),
        .kdf_grant           (kdf_grant),
        .kdf_init            (kdf_init),
        .kdf_hard_init       (kdf_hard_init),
        .kdf_mode            (kdf_mode),
        .kdf_wr_en           (kdf_wr_en),
        .kdf_din             (kdf_din),
        .kdf_wr_xor          (kdf_wr_xor),
        .kdf_wr_last         (kdf_wr_last),
        .kdf_rd_en           (kdf_rd_en),
        .kdf_rd_extend       (kdf_rd_extend),

        .sh_busy             (sh_busy),
        .sh_idle             (sh_idle),
        .sh_dout             (sh_dout),
        .sh_dout_valid       (sh_dout_valid),
        .sh_done             (sh_done),
        .sh_done_extend      (sh_done_extend),
        .sh_dout_rate_words  (sh_dout_rate_words)
    );

    // The full Kyber-512 Server/Client loopback is instantiated inside
    // riscv_soc and controlled by firmware through its AXI-Lite registers.

endmodule
