`timescale 1ns / 1ps
`default_nettype none

//-----------------------------------------------------------------------------
// kdf_keccak.v - Fixed-profile KDF between the fuzzy extractor and ML-KEM-512.
//
// Function: SHAKE256(key_in[191:0] as 24 little-endian bytes, 64 output
// bytes).
//
// SHARED-HARDWARE REBUILD: this module no longer instantiates its own
// keccak_f1600_server (and its 1600-bit state register).  It is client 1 of
// keccak_shared_arbiter and drives the SAME sha3_shake_core that the Kyber
// hash_core_Server uses.
//
// The legacy shift-register protocol (50 clear shifts + 32 shift/absorb
// cycles + 16 squeeze shifts through a 1600-bit register) is replaced by a
// single pre-padded SHAKE256 rate block, which is exactly what the shared
// core's pre_padded=1 mode consumes:
//
//     word  0.. 5 : key_in, little-endian 32-bit words
//     word      6 : SHAKE256 delimited suffix 0x0000001F
//     word  7..32 : zero fill
//     word     33 : 0x80000000  (final pad10*1 bit, byte 135)
//
// then 16 squeeze words are read straight out of the permutation state.
// seed_out packing is bit-identical to the legacy version: the first
// squeezed word ends up in seed_out[511:480].
//-----------------------------------------------------------------------------

module kdf_keccak (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [191:0] key_in,
    output reg          done,
    output reg  [511:0] seed_out,

    // ---------------- shared Keccak hardware (arbiter client 1) ----------------
    output reg          kdf_req,        // held high for the whole transaction
    input  wire         kdf_grant,
    output reg          kdf_init,
    output reg          kdf_hard_init,
    output wire [1:0]   kdf_mode,
    output reg          kdf_wr_en,
    output reg  [31:0]  kdf_din,
    output wire         kdf_wr_xor,
    output reg          kdf_wr_last,
    output reg          kdf_rd_en,
    output wire         kdf_rd_extend,
    input  wire         sh_done,
    input  wire         sh_dout_valid,
    input  wire [31:0]  sh_dout
);

    localparam [2:0] ST_IDLE       = 3'd0;
    localparam [2:0] ST_WAIT_GRANT = 3'd1;
    localparam [2:0] ST_INIT       = 3'd2;
    localparam [2:0] ST_ABSORB     = 3'd3;
    localparam [2:0] ST_PERM_WAIT  = 3'd4;
    localparam [2:0] ST_SQUEEZE    = 3'd5;
    localparam [2:0] ST_DONE       = 3'd6;

    reg [2:0]   state;
    reg [2:0]   next_state;
    reg [5:0]   word_count;
    reg [191:0] key_shift;

    assign kdf_mode      = 2'd1;   // SHAKE256
    assign kdf_wr_xor    = 1'b0;   // fresh block: overwrite, do not chain
    assign kdf_rd_extend = 1'b0;   // 64 output bytes fit in the first rate

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= ST_IDLE;
            word_count <= 6'd0;
            key_shift  <= 192'd0;
            seed_out   <= 512'd0;
            done       <= 1'b0;
            kdf_req    <= 1'b0;
        end else begin
            state <= next_state;
            done  <= 1'b0;

            case (state)
                ST_IDLE: begin
                    if (start) begin
                        kdf_req    <= 1'b1;
                        key_shift  <= key_in;
                        seed_out   <= 512'd0;
                        word_count <= 6'd0;
                    end
                end

                ST_WAIT_GRANT:
                    if (kdf_grant)
                        word_count <= 6'd0;

                ST_ABSORB: begin
                    word_count <= word_count + 6'd1;
                    if (word_count < 6'd6)
                        key_shift <= {32'd0, key_shift[191:32]};
                end
                
                // FIX: word_count đã bị cuốn lên 34 sau ST_ABSORB (do tăng trên cùng
                // cạnh clock chuyển state). Phải reset về 0 khi bước sang squeeze,
                // nếu không kdf_rd_en/next_state trong ST_SQUEEZE sẽ không bao giờ
                // đúng cho tới khi word_count (6-bit) tự cuốn vòng lại.
              ST_PERM_WAIT:
                  if (sh_done)
                      word_count <= 6'd0;

                ST_SQUEEZE: begin
                    // Capture first, then rotate: sh_dout shows the current
                    // word while kdf_rd_en requests the next one.
                    word_count <= word_count + 6'd1;
                    seed_out   <= {sh_dout, seed_out[511:32]};
                end

                ST_DONE: begin
                    done    <= 1'b1;
                    kdf_req <= 1'b0;
                end

                default: ;
            endcase
        end
    end

    always @* begin
        next_state    = state;
        kdf_init      = 1'b0;
        kdf_hard_init = 1'b0;
        kdf_wr_en     = 1'b0;
        kdf_din       = 32'd0;
        kdf_wr_last   = 1'b0;
        kdf_rd_en     = 1'b0;

        case (state)
            ST_IDLE:
                if (start)
                    next_state = ST_WAIT_GRANT;

            // The arbiter only grants at a fully-idle core, so this wait is
            // safe: no Kyber permutation or squeeze stream is disturbed.
            ST_WAIT_GRANT:
                if (kdf_grant)
                    next_state = ST_INIT;

            ST_INIT: begin
                kdf_init      = 1'b1;
                kdf_hard_init = 1'b1;
                next_state    = ST_ABSORB;
            end

            // Push the complete pre-padded 34-word SHAKE256 rate block.
            ST_ABSORB: begin
                kdf_wr_en = 1'b1;
                if (word_count < 6'd6)
                    kdf_din = key_shift[31:0];
                else if (word_count == 6'd6)
                    kdf_din = 32'h0000001f;
                else if (word_count == 6'd33)
                    kdf_din = 32'h80000000;
                else
                    kdf_din = 32'd0;
                kdf_wr_last = (word_count == 6'd33);
                if (word_count == 6'd33)
                    next_state = ST_PERM_WAIT;
            end

            ST_PERM_WAIT:
                if (sh_done)
                    next_state = ST_SQUEEZE;

            // 16 words = 64 bytes, all inside the first SHAKE256 rate block.
            ST_SQUEEZE: begin
                if (word_count < 6'd15)
                    kdf_rd_en = sh_dout_valid;
                if (word_count == 6'd15)
                    next_state = ST_DONE;
            end

            ST_DONE:
                if (!start)
                    next_state = ST_IDLE;

            default: next_state = ST_IDLE;
        endcase
    end

endmodule

`default_nettype wire