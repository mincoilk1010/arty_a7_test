`timescale 1ns / 1ps
//-----------------------------------------------------------------------------
// ALGORITHM.v - 1 round Keccak-f1600, output registered
// Tương đương VHDL Round: theta→rho→pi→chi→iota + RegisterFDRE
// Cùng port list với ALGORITHM legacy → drop-in, không sửa gì khác.
//
// FIX v2 (LUT-optimized):
//   * RHO: bỏ function rotl() (Vivado có thể infer barrel shifter 64-bit
//     → vài trăm LUT). Thay bằng wire-routing tường minh từng lane → 0 LUT.
//   * Register: đổi sync reset → async reset để map vào primitive FDRE
//     (chân R cứng), tránh mux 2:1 trước D trên 1600 bit → tiết kiệm ~1600 LUT.
//-----------------------------------------------------------------------------
module ALGORITHM (
    input  wire          Clk,
    input  wire          reset,
    input  wire          en_in,
    input  wire          en_ctr,
    input  wire [1599:0] padding_in,
    input  wire [4:0]    RC_id_in,
    output wire [4:0]    RC_flag,
    output wire [1599:0] data_out
);

    // ---------- Round constant -------------------------------------------
    reg [63:0] rc;
    always @(*) case (RC_id_in)
        5'd0:  rc = 64'h0000000000000001;  5'd1:  rc = 64'h0000000000008082;
        5'd2:  rc = 64'h800000000000808A;  5'd3:  rc = 64'h8000000080008000;
        5'd4:  rc = 64'h000000000000808B;  5'd5:  rc = 64'h0000000080000001;
        5'd6:  rc = 64'h8000000080008081;  5'd7:  rc = 64'h8000000000008009;
        5'd8:  rc = 64'h000000000000008A;  5'd9:  rc = 64'h0000000000000088;
        5'd10: rc = 64'h0000000080008009;  5'd11: rc = 64'h000000008000000A;
        5'd12: rc = 64'h000000008000808B;  5'd13: rc = 64'h800000000000008B;
        5'd14: rc = 64'h8000000000008089;  5'd15: rc = 64'h8000000000008003;
        5'd16: rc = 64'h8000000000008002;  5'd17: rc = 64'h8000000000000080;
        5'd18: rc = 64'h000000000000800A;  5'd19: rc = 64'h800000008000000A;
        5'd20: rc = 64'h8000000080008081;  5'd21: rc = 64'h8000000000008080;
        5'd22: rc = 64'h0000000080000001;  5'd23: rc = 64'h8000000080008008;
        default: rc = 64'h0;
    endcase

    // ---------- Lane extract: lane(x,y) = bit (x+5y)*64 ----------
    wire [63:0] A [0:4][0:4];
    genvar x, y;
    generate
      for (y = 0; y < 5; y = y + 1)
        for (x = 0; x < 5; x = x + 1)
          assign A[x][y] = padding_in[64*(x + 5*y) +: 64];
    endgenerate

    // ---------- THETA ----------
    wire [63:0] C [0:4], D [0:4];
    assign C[0] = A[0][0]^A[0][1]^A[0][2]^A[0][3]^A[0][4];
    assign C[1] = A[1][0]^A[1][1]^A[1][2]^A[1][3]^A[1][4];
    assign C[2] = A[2][0]^A[2][1]^A[2][2]^A[2][3]^A[2][4];
    assign C[3] = A[3][0]^A[3][1]^A[3][2]^A[3][3]^A[3][4];
    assign C[4] = A[4][0]^A[4][1]^A[4][2]^A[4][3]^A[4][4];
    assign D[0] = C[4] ^ {C[1][62:0], C[1][63]};
    assign D[1] = C[0] ^ {C[2][62:0], C[2][63]};
    assign D[2] = C[1] ^ {C[3][62:0], C[3][63]};
    assign D[3] = C[2] ^ {C[4][62:0], C[4][63]};
    assign D[4] = C[3] ^ {C[0][62:0], C[0][63]};

    wire [63:0] B [0:4][0:4];
    generate
      for (y = 0; y < 5; y = y + 1)
        for (x = 0; x < 5; x = x + 1)
          assign B[x][y] = A[x][y] ^ D[x];
    endgenerate

    // ---------- RHO (hard-wired bit routing, 0 LUT) ----------
    // rotl(v, n) = {v[63-n:0], v[63:64-n]}   với 1 <= n <= 63
    // rotl(v, 0) = v
    wire [63:0] C2 [0:4][0:4];

    // x=0..4, y=0
    assign C2[0][0] = B[0][0];                                  // n=0
    assign C2[1][0] = {B[1][0][62:0], B[1][0][63]};             // n=1
    assign C2[2][0] = {B[2][0][ 1:0], B[2][0][63: 2]};          // n=62
    assign C2[3][0] = {B[3][0][35:0], B[3][0][63:36]};          // n=28
    assign C2[4][0] = {B[4][0][36:0], B[4][0][63:37]};          // n=27

    // y=1
    assign C2[0][1] = {B[0][1][27:0], B[0][1][63:28]};          // n=36
    assign C2[1][1] = {B[1][1][19:0], B[1][1][63:20]};          // n=44
    assign C2[2][1] = {B[2][1][57:0], B[2][1][63:58]};          // n=6
    assign C2[3][1] = {B[3][1][ 8:0], B[3][1][63: 9]};          // n=55
    assign C2[4][1] = {B[4][1][43:0], B[4][1][63:44]};          // n=20

    // y=2
    assign C2[0][2] = {B[0][2][60:0], B[0][2][63:61]};          // n=3
    assign C2[1][2] = {B[1][2][53:0], B[1][2][63:54]};          // n=10
    assign C2[2][2] = {B[2][2][20:0], B[2][2][63:21]};          // n=43
    assign C2[3][2] = {B[3][2][38:0], B[3][2][63:39]};          // n=25
    assign C2[4][2] = {B[4][2][24:0], B[4][2][63:25]};          // n=39

    // y=3
    assign C2[0][3] = {B[0][3][22:0], B[0][3][63:23]};          // n=41
    assign C2[1][3] = {B[1][3][18:0], B[1][3][63:19]};          // n=45
    assign C2[2][3] = {B[2][3][48:0], B[2][3][63:49]};          // n=15
    assign C2[3][3] = {B[3][3][42:0], B[3][3][63:43]};          // n=21
    assign C2[4][3] = {B[4][3][55:0], B[4][3][63:56]};          // n=8

    // y=4
    assign C2[0][4] = {B[0][4][45:0], B[0][4][63:46]};          // n=18
    assign C2[1][4] = {B[1][4][61:0], B[1][4][63:62]};          // n=2
    assign C2[2][4] = {B[2][4][ 2:0], B[2][4][63: 3]};          // n=61
    assign C2[3][4] = {B[3][4][ 7:0], B[3][4][63: 8]};          // n=56
    assign C2[4][4] = {B[4][4][49:0], B[4][4][63:50]};          // n=14

    // ---------- PI ----------
    wire [63:0] D2 [0:4][0:4];
    generate
      for (y = 0; y < 5; y = y + 1)
        for (x = 0; x < 5; x = x + 1)
          assign D2[y][(2*x + 3*y) % 5] = C2[x][y];
    endgenerate

    // ---------- CHI ----------
    wire [63:0] E [0:4][0:4];
    generate
      for (y = 0; y < 5; y = y + 1)
        for (x = 0; x < 5; x = x + 1)
          assign E[x][y] = D2[x][y] ^ (~D2[(x+1)%5][y] & D2[(x+2)%5][y]);
    endgenerate

    // ---------- IOTA ----------
    wire [63:0] F [0:4][0:4];
    generate
      for (y = 0; y < 5; y = y + 1)
        for (x = 0; x < 5; x = x + 1)
          assign F[x][y] = (x == 0 && y == 0) ? (E[0][0] ^ rc) : E[x][y];
    endgenerate

    // ---------- Pack về 1600-bit ----------
    wire [1599:0] round_out;
    generate
      for (y = 0; y < 5; y = y + 1)
        for (x = 0; x < 5; x = x + 1)
          assign round_out[64*(x + 5*y) +: 64] = F[x][y];
    endgenerate

    // ---------- Register: async reset → FDRE primitive (0 LUT cho reset) ----------
    // Giữ nguyên polarity như bản cũ (`if (reset)` clear). Async reset map
    // thẳng vào chân R cứng của FDRE trong 7-series, không cần mux trước D.
    reg [1599:0] state_q;
    always @(posedge Clk or posedge reset) begin
        if (reset)          state_q <= 1600'd0;
        else if (en_in)     state_q <= round_out;
    end

    assign data_out = state_q;
    assign RC_flag  = RC_id_in;

endmodule