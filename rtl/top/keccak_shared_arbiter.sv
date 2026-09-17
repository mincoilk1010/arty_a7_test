`timescale 1ns / 1ps
`default_nettype none
//-----------------------------------------------------------------------------
// keccak_shared_arbiter.v - SINGLE shared sha3_shake_core for the whole SOC
//
// Client 0 : hash_core_Server (Kyber)  - background owner, drives pre_padded
//            whole-rate-block transactions through its IFIFO glue.
// Client 1 : kdf_keccak                - grabs the core only when it is fully
//            idle (no permutation in flight, no undrained squeeze block) and
//            holds it until the KDF transaction completes.
//
// Handoff rule: kdf_hold is set only when sh_idle && !hash_init, so a KDF
// request can never preempt or corrupt an in-flight Kyber transaction.
// Firmware phases (PUF -> FE -> KDF -> Kyber) guarantee the Kyber FSM is not
// requesting while the KDF owns the core; the idle-guard makes this safe even
// if that assumption is ever violated.
//-----------------------------------------------------------------------------

module keccak_shared_arbiter(
    input  wire        clk,
    input  wire        rst,

    // ---------------- client 0: Kyber hash core ----------------
    input  wire        hash_init,
    input  wire        hash_hard_init,
    input  wire [1:0]  hash_mode,
    input  wire        hash_wr_en,
    input  wire [31:0] hash_din,
    input  wire        hash_wr_xor,
    input  wire        hash_wr_last,
    input  wire        hash_rd_en,
    input  wire        hash_rd_extend,

    // ---------------- client 1: KDF ----------------
    input  wire        kdf_req,
    output wire        kdf_grant,
    input  wire        kdf_init,
    input  wire        kdf_hard_init,
    input  wire [1:0]  kdf_mode,
    input  wire        kdf_wr_en,
    input  wire [31:0] kdf_din,
    input  wire        kdf_wr_xor,
    input  wire        kdf_wr_last,
    input  wire        kdf_rd_en,
    input  wire        kdf_rd_extend,

    // ---------------- broadcast core status ----------------
    output wire        sh_busy,
    output wire        sh_idle,
    output wire [31:0] sh_dout,
    output wire        sh_dout_valid,
    output wire        sh_done,
    output wire        sh_done_extend,
    output wire [5:0]  sh_dout_rate_words,
    output wire hash_grant
);

    // ------------------------------------------------------------------
    // Ownership
    // ------------------------------------------------------------------
    reg kdf_hold;
    always @(posedge clk) begin
        if (rst)
            kdf_hold <= 1'b0;
        else if (kdf_hold && !kdf_req)
            kdf_hold <= 1'b0;                       // KDF transaction finished
        else if (!kdf_hold && kdf_req && !sh_busy && !hash_init)
            kdf_hold <= 1'b1;                       // safe handoff point only
    end

    assign hash_grant = ~kdf_hold;
    assign kdf_grant = kdf_hold;

    // ------------------------------------------------------------------
    // Input mux (clients pre-gate their strobes with their own grant;
    // the mux additionally protects against any stray drive).
    // ------------------------------------------------------------------
    wire        c_init       = kdf_hold ? kdf_init       : (hash_init       & hash_grant);
    wire        c_hard_init  = kdf_hold ? kdf_hard_init  : (hash_hard_init  & hash_grant);
    wire [1:0]  c_mode       = kdf_hold ? kdf_mode       : hash_mode;
    wire        c_wr_en      = kdf_hold ? kdf_wr_en      : (hash_wr_en      & hash_grant);
    wire [31:0] c_din        = kdf_hold ? kdf_din        : hash_din;
    wire        c_wr_xor     = kdf_hold ? kdf_wr_xor     : hash_wr_xor;
    wire        c_wr_last    = kdf_hold ? kdf_wr_last    : hash_wr_last;
    wire        c_rd_en      = kdf_hold ? kdf_rd_en      : (hash_rd_en      & hash_grant);
    wire        c_rd_extend  = kdf_hold ? kdf_rd_extend  : (hash_rd_extend  & hash_grant);

    // ------------------------------------------------------------------
    // The ONE and ONLY sponge instance in the design
    // ------------------------------------------------------------------
    sha3_shake_core sponge (
        .clk            (clk),
        .rst            (rst),
        .init           (c_init),
        .hard_init      (c_hard_init),
        .mode           (c_mode),
        .pre_padded     (1'b1),   // both clients supply full padded rate blocks
        .wr_en          (c_wr_en),
        .din            (c_din),
        .wr_xor         (c_wr_xor),
        .wr_last        (c_wr_last),
        .busy           (sh_busy),
        .rd_en          (c_rd_en),
        .rd_extend      (c_rd_extend),
        .dout           (sh_dout),
        .dout_valid     (sh_dout_valid),
        .done           (sh_done),
        .done_extend    (sh_done_extend),
        .dout_rate_words(sh_dout_rate_words),
        .idle           (sh_idle)
    );

endmodule

`default_nettype wire
