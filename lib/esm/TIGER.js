"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TIGER = exports.TIGER2_192_HMAC = exports.TIGER2_192 = exports.TIGER2_160_HMAC = exports.TIGER2_160 = exports.TIGER2_128_HMAC = exports.TIGER2_128 = exports.TIGER2_HMAC = exports.TIGER2 = exports.TIGER192_HMAC = exports.TIGER192 = exports.TIGER160_HMAC = exports.TIGER160 = exports.TIGER128_HMAC = exports.TIGER128 = exports.TIGER_HMAC = exports._TIGER = exports.Tiger = void 0;
var t1;
var t2;
var t3;
var t4;
const uint = BigInt.asUintN.bind(BigInt, 64);
const U64 = BigInt("0xffffffffffffffff");
// Turn a buffer into a Tiger-padded array of 64-bit words
function _getMessage(buffer, tiger2) {
    const words = [];
    let word = BigInt(0);
    let byteLen = BigInt(0);
    for (const c of buffer) {
        const b = byteLen++ & BigInt(0x7);
        word |= BigInt(c) << (b << BigInt(3));
        if (byteLen % BigInt(8) == BigInt(0)) {
            words.push(word);
            word = BigInt(0);
        }
    }
    // Store original size (in bits)
    const bitSize = (byteLen << BigInt(3)) & U64;
    // Pad our message with a byte of 0x1 ala MD4 (Tiger1) padding
    const paddingByte = tiger2 ? BigInt(0x80) : BigInt(0x1);
    const b = byteLen & BigInt(0x7);
    if (b) {
        word |= paddingByte << (b << BigInt(3));
        words.push(word);
        byteLen += BigInt(8) - b;
    }
    else {
        words.push(paddingByte);
        byteLen += BigInt(8);
    }
    for (byteLen %= BigInt(64); byteLen < BigInt(56); byteLen += BigInt(8)) {
        words.push(BigInt(0));
    }
    words.push(bitSize);
    return words;
}
function writeUint64(buf, value, isLittleEndian, offset) {
    const dataView = new DataView(buf.buffer);
    dataView.setBigUint64(offset, value, isLittleEndian);
}
var inited = false;
function arrayType() {
    if (typeof window !== 'undefined') {
        return "array";
    }
    else {
        return "buffer";
    }
}
;
/**
 * Calculates Tiger 128, 160, 192 hash
 */
class Tiger {
    /**
     * Calculates Tiger 128, 160, 192 hash
     *
     * @param {128|160|192} digestBitLen - Return bit length
     * @param {number} extraPasses - For additional passes after the first 3.  For 'Tiger,4' we'd pass 1 here
     * @param {boolean} bigEndian - PHP originally had the final byte-order of the digest inverted.  If this old behavior is desired, set this to true.
     * @param {boolean} tiger2 - for Tiger2 hash instead
     */
    constructor(digestBitLen = 128, // 128, 160, 192
    extraPasses = 0, bigEndian = false, tiger2 = false) {
        this._a = { value: BigInt(0) };
        this._b = { value: BigInt(0) };
        this._c = { value: BigInt(0) };
        this._aa = BigInt(0);
        this._bb = BigInt(0);
        this._cc = BigInt(0);
        this._x0 = BigInt(0);
        this._x1 = BigInt(0);
        this._x2 = BigInt(0);
        this._x3 = BigInt(0);
        this._x4 = BigInt(0);
        this._x5 = BigInt(0);
        this._x6 = BigInt(0);
        this._x7 = BigInt(0);
        if (!inited) {
            t1 = [
                BigInt("0x02AAB17CF7E90C5E") /*    0 */, BigInt("0xAC424B03E243A8EC") /*    1 */,
                BigInt("0x72CD5BE30DD5FCD3") /*    2 */, BigInt("0x6D019B93F6F97F3A") /*    3 */,
                BigInt("0xCD9978FFD21F9193") /*    4 */, BigInt("0x7573A1C9708029E2") /*    5 */,
                BigInt("0xB164326B922A83C3") /*    6 */, BigInt("0x46883EEE04915870") /*    7 */,
                BigInt("0xEAACE3057103ECE6") /*    8 */, BigInt("0xC54169B808A3535C") /*    9 */,
                BigInt("0x4CE754918DDEC47C") /*   10 */, BigInt("0x0AA2F4DFDC0DF40C") /*   11 */,
                BigInt("0x10B76F18A74DBEFA") /*   12 */, BigInt("0xC6CCB6235AD1AB6A") /*   13 */,
                BigInt("0x13726121572FE2FF") /*   14 */, BigInt("0x1A488C6F199D921E") /*   15 */,
                BigInt("0x4BC9F9F4DA0007CA") /*   16 */, BigInt("0x26F5E6F6E85241C7") /*   17 */,
                BigInt("0x859079DBEA5947B6") /*   18 */, BigInt("0x4F1885C5C99E8C92") /*   19 */,
                BigInt("0xD78E761EA96F864B") /*   20 */, BigInt("0x8E36428C52B5C17D") /*   21 */,
                BigInt("0x69CF6827373063C1") /*   22 */, BigInt("0xB607C93D9BB4C56E") /*   23 */,
                BigInt("0x7D820E760E76B5EA") /*   24 */, BigInt("0x645C9CC6F07FDC42") /*   25 */,
                BigInt("0xBF38A078243342E0") /*   26 */, BigInt("0x5F6B343C9D2E7D04") /*   27 */,
                BigInt("0xF2C28AEB600B0EC6") /*   28 */, BigInt("0x6C0ED85F7254BCAC") /*   29 */,
                BigInt("0x71592281A4DB4FE5") /*   30 */, BigInt("0x1967FA69CE0FED9F") /*   31 */,
                BigInt("0xFD5293F8B96545DB") /*   32 */, BigInt("0xC879E9D7F2A7600B") /*   33 */,
                BigInt("0x860248920193194E") /*   34 */, BigInt("0xA4F9533B2D9CC0B3") /*   35 */,
                BigInt("0x9053836C15957613") /*   36 */, BigInt("0xDB6DCF8AFC357BF1") /*   37 */,
                BigInt("0x18BEEA7A7A370F57") /*   38 */, BigInt("0x037117CA50B99066") /*   39 */,
                BigInt("0x6AB30A9774424A35") /*   40 */, BigInt("0xF4E92F02E325249B") /*   41 */,
                BigInt("0x7739DB07061CCAE1") /*   42 */, BigInt("0xD8F3B49CECA42A05") /*   43 */,
                BigInt("0xBD56BE3F51382F73") /*   44 */, BigInt("0x45FAED5843B0BB28") /*   45 */,
                BigInt("0x1C813D5C11BF1F83") /*   46 */, BigInt("0x8AF0E4B6D75FA169") /*   47 */,
                BigInt("0x33EE18A487AD9999") /*   48 */, BigInt("0x3C26E8EAB1C94410") /*   49 */,
                BigInt("0xB510102BC0A822F9") /*   50 */, BigInt("0x141EEF310CE6123B") /*   51 */,
                BigInt("0xFC65B90059DDB154") /*   52 */, BigInt("0xE0158640C5E0E607") /*   53 */,
                BigInt("0x884E079826C3A3CF") /*   54 */, BigInt("0x930D0D9523C535FD") /*   55 */,
                BigInt("0x35638D754E9A2B00") /*   56 */, BigInt("0x4085FCCF40469DD5") /*   57 */,
                BigInt("0xC4B17AD28BE23A4C") /*   58 */, BigInt("0xCAB2F0FC6A3E6A2E") /*   59 */,
                BigInt("0x2860971A6B943FCD") /*   60 */, BigInt("0x3DDE6EE212E30446") /*   61 */,
                BigInt("0x6222F32AE01765AE") /*   62 */, BigInt("0x5D550BB5478308FE") /*   63 */,
                BigInt("0xA9EFA98DA0EDA22A") /*   64 */, BigInt("0xC351A71686C40DA7") /*   65 */,
                BigInt("0x1105586D9C867C84") /*   66 */, BigInt("0xDCFFEE85FDA22853") /*   67 */,
                BigInt("0xCCFBD0262C5EEF76") /*   68 */, BigInt("0xBAF294CB8990D201") /*   69 */,
                BigInt("0xE69464F52AFAD975") /*   70 */, BigInt("0x94B013AFDF133E14") /*   71 */,
                BigInt("0x06A7D1A32823C958") /*   72 */, BigInt("0x6F95FE5130F61119") /*   73 */,
                BigInt("0xD92AB34E462C06C0") /*   74 */, BigInt("0xED7BDE33887C71D2") /*   75 */,
                BigInt("0x79746D6E6518393E") /*   76 */, BigInt("0x5BA419385D713329") /*   77 */,
                BigInt("0x7C1BA6B948A97564") /*   78 */, BigInt("0x31987C197BFDAC67") /*   79 */,
                BigInt("0xDE6C23C44B053D02") /*   80 */, BigInt("0x581C49FED002D64D") /*   81 */,
                BigInt("0xDD474D6338261571") /*   82 */, BigInt("0xAA4546C3E473D062") /*   83 */,
                BigInt("0x928FCE349455F860") /*   84 */, BigInt("0x48161BBACAAB94D9") /*   85 */,
                BigInt("0x63912430770E6F68") /*   86 */, BigInt("0x6EC8A5E602C6641C") /*   87 */,
                BigInt("0x87282515337DDD2B") /*   88 */, BigInt("0x2CDA6B42034B701B") /*   89 */,
                BigInt("0xB03D37C181CB096D") /*   90 */, BigInt("0xE108438266C71C6F") /*   91 */,
                BigInt("0x2B3180C7EB51B255") /*   92 */, BigInt("0xDF92B82F96C08BBC") /*   93 */,
                BigInt("0x5C68C8C0A632F3BA") /*   94 */, BigInt("0x5504CC861C3D0556") /*   95 */,
                BigInt("0xABBFA4E55FB26B8F") /*   96 */, BigInt("0x41848B0AB3BACEB4") /*   97 */,
                BigInt("0xB334A273AA445D32") /*   98 */, BigInt("0xBCA696F0A85AD881") /*   99 */,
                BigInt("0x24F6EC65B528D56C") /*  100 */, BigInt("0x0CE1512E90F4524A") /*  101 */,
                BigInt("0x4E9DD79D5506D35A") /*  102 */, BigInt("0x258905FAC6CE9779") /*  103 */,
                BigInt("0x2019295B3E109B33") /*  104 */, BigInt("0xF8A9478B73A054CC") /*  105 */,
                BigInt("0x2924F2F934417EB0") /*  106 */, BigInt("0x3993357D536D1BC4") /*  107 */,
                BigInt("0x38A81AC21DB6FF8B") /*  108 */, BigInt("0x47C4FBF17D6016BF") /*  109 */,
                BigInt("0x1E0FAADD7667E3F5") /*  110 */, BigInt("0x7ABCFF62938BEB96") /*  111 */,
                BigInt("0xA78DAD948FC179C9") /*  112 */, BigInt("0x8F1F98B72911E50D") /*  113 */,
                BigInt("0x61E48EAE27121A91") /*  114 */, BigInt("0x4D62F7AD31859808") /*  115 */,
                BigInt("0xECEBA345EF5CEAEB") /*  116 */, BigInt("0xF5CEB25EBC9684CE") /*  117 */,
                BigInt("0xF633E20CB7F76221") /*  118 */, BigInt("0xA32CDF06AB8293E4") /*  119 */,
                BigInt("0x985A202CA5EE2CA4") /*  120 */, BigInt("0xCF0B8447CC8A8FB1") /*  121 */,
                BigInt("0x9F765244979859A3") /*  122 */, BigInt("0xA8D516B1A1240017") /*  123 */,
                BigInt("0x0BD7BA3EBB5DC726") /*  124 */, BigInt("0xE54BCA55B86ADB39") /*  125 */,
                BigInt("0x1D7A3AFD6C478063") /*  126 */, BigInt("0x519EC608E7669EDD") /*  127 */,
                BigInt("0x0E5715A2D149AA23") /*  128 */, BigInt("0x177D4571848FF194") /*  129 */,
                BigInt("0xEEB55F3241014C22") /*  130 */, BigInt("0x0F5E5CA13A6E2EC2") /*  131 */,
                BigInt("0x8029927B75F5C361") /*  132 */, BigInt("0xAD139FABC3D6E436") /*  133 */,
                BigInt("0x0D5DF1A94CCF402F") /*  134 */, BigInt("0x3E8BD948BEA5DFC8") /*  135 */,
                BigInt("0xA5A0D357BD3FF77E") /*  136 */, BigInt("0xA2D12E251F74F645") /*  137 */,
                BigInt("0x66FD9E525E81A082") /*  138 */, BigInt("0x2E0C90CE7F687A49") /*  139 */,
                BigInt("0xC2E8BCBEBA973BC5") /*  140 */, BigInt("0x000001BCE509745F") /*  141 */,
                BigInt("0x423777BBE6DAB3D6") /*  142 */, BigInt("0xD1661C7EAEF06EB5") /*  143 */,
                BigInt("0xA1781F354DAACFD8") /*  144 */, BigInt("0x2D11284A2B16AFFC") /*  145 */,
                BigInt("0xF1FC4F67FA891D1F") /*  146 */, BigInt("0x73ECC25DCB920ADA") /*  147 */,
                BigInt("0xAE610C22C2A12651") /*  148 */, BigInt("0x96E0A810D356B78A") /*  149 */,
                BigInt("0x5A9A381F2FE7870F") /*  150 */, BigInt("0xD5AD62EDE94E5530") /*  151 */,
                BigInt("0xD225E5E8368D1427") /*  152 */, BigInt("0x65977B70C7AF4631") /*  153 */,
                BigInt("0x99F889B2DE39D74F") /*  154 */, BigInt("0x233F30BF54E1D143") /*  155 */,
                BigInt("0x9A9675D3D9A63C97") /*  156 */, BigInt("0x5470554FF334F9A8") /*  157 */,
                BigInt("0x166ACB744A4F5688") /*  158 */, BigInt("0x70C74CAAB2E4AEAD") /*  159 */,
                BigInt("0xF0D091646F294D12") /*  160 */, BigInt("0x57B82A89684031D1") /*  161 */,
                BigInt("0xEFD95A5A61BE0B6B") /*  162 */, BigInt("0x2FBD12E969F2F29A") /*  163 */,
                BigInt("0x9BD37013FEFF9FE8") /*  164 */, BigInt("0x3F9B0404D6085A06") /*  165 */,
                BigInt("0x4940C1F3166CFE15") /*  166 */, BigInt("0x09542C4DCDF3DEFB") /*  167 */,
                BigInt("0xB4C5218385CD5CE3") /*  168 */, BigInt("0xC935B7DC4462A641") /*  169 */,
                BigInt("0x3417F8A68ED3B63F") /*  170 */, BigInt("0xB80959295B215B40") /*  171 */,
                BigInt("0xF99CDAEF3B8C8572") /*  172 */, BigInt("0x018C0614F8FCB95D") /*  173 */,
                BigInt("0x1B14ACCD1A3ACDF3") /*  174 */, BigInt("0x84D471F200BB732D") /*  175 */,
                BigInt("0xC1A3110E95E8DA16") /*  176 */, BigInt("0x430A7220BF1A82B8") /*  177 */,
                BigInt("0xB77E090D39DF210E") /*  178 */, BigInt("0x5EF4BD9F3CD05E9D") /*  179 */,
                BigInt("0x9D4FF6DA7E57A444") /*  180 */, BigInt("0xDA1D60E183D4A5F8") /*  181 */,
                BigInt("0xB287C38417998E47") /*  182 */, BigInt("0xFE3EDC121BB31886") /*  183 */,
                BigInt("0xC7FE3CCC980CCBEF") /*  184 */, BigInt("0xE46FB590189BFD03") /*  185 */,
                BigInt("0x3732FD469A4C57DC") /*  186 */, BigInt("0x7EF700A07CF1AD65") /*  187 */,
                BigInt("0x59C64468A31D8859") /*  188 */, BigInt("0x762FB0B4D45B61F6") /*  189 */,
                BigInt("0x155BAED099047718") /*  190 */, BigInt("0x68755E4C3D50BAA6") /*  191 */,
                BigInt("0xE9214E7F22D8B4DF") /*  192 */, BigInt("0x2ADDBF532EAC95F4") /*  193 */,
                BigInt("0x32AE3909B4BD0109") /*  194 */, BigInt("0x834DF537B08E3450") /*  195 */,
                BigInt("0xFA209DA84220728D") /*  196 */, BigInt("0x9E691D9B9EFE23F7") /*  197 */,
                BigInt("0x0446D288C4AE8D7F") /*  198 */, BigInt("0x7B4CC524E169785B") /*  199 */,
                BigInt("0x21D87F0135CA1385") /*  200 */, BigInt("0xCEBB400F137B8AA5") /*  201 */,
                BigInt("0x272E2B66580796BE") /*  202 */, BigInt("0x3612264125C2B0DE") /*  203 */,
                BigInt("0x057702BDAD1EFBB2") /*  204 */, BigInt("0xD4BABB8EACF84BE9") /*  205 */,
                BigInt("0x91583139641BC67B") /*  206 */, BigInt("0x8BDC2DE08036E024") /*  207 */,
                BigInt("0x603C8156F49F68ED") /*  208 */, BigInt("0xF7D236F7DBEF5111") /*  209 */,
                BigInt("0x9727C4598AD21E80") /*  210 */, BigInt("0xA08A0896670A5FD7") /*  211 */,
                BigInt("0xCB4A8F4309EBA9CB") /*  212 */, BigInt("0x81AF564B0F7036A1") /*  213 */,
                BigInt("0xC0B99AA778199ABD") /*  214 */, BigInt("0x959F1EC83FC8E952") /*  215 */,
                BigInt("0x8C505077794A81B9") /*  216 */, BigInt("0x3ACAAF8F056338F0") /*  217 */,
                BigInt("0x07B43F50627A6778") /*  218 */, BigInt("0x4A44AB49F5ECCC77") /*  219 */,
                BigInt("0x3BC3D6E4B679EE98") /*  220 */, BigInt("0x9CC0D4D1CF14108C") /*  221 */,
                BigInt("0x4406C00B206BC8A0") /*  222 */, BigInt("0x82A18854C8D72D89") /*  223 */,
                BigInt("0x67E366B35C3C432C") /*  224 */, BigInt("0xB923DD61102B37F2") /*  225 */,
                BigInt("0x56AB2779D884271D") /*  226 */, BigInt("0xBE83E1B0FF1525AF") /*  227 */,
                BigInt("0xFB7C65D4217E49A9") /*  228 */, BigInt("0x6BDBE0E76D48E7D4") /*  229 */,
                BigInt("0x08DF828745D9179E") /*  230 */, BigInt("0x22EA6A9ADD53BD34") /*  231 */,
                BigInt("0xE36E141C5622200A") /*  232 */, BigInt("0x7F805D1B8CB750EE") /*  233 */,
                BigInt("0xAFE5C7A59F58E837") /*  234 */, BigInt("0xE27F996A4FB1C23C") /*  235 */,
                BigInt("0xD3867DFB0775F0D0") /*  236 */, BigInt("0xD0E673DE6E88891A") /*  237 */,
                BigInt("0x123AEB9EAFB86C25") /*  238 */, BigInt("0x30F1D5D5C145B895") /*  239 */,
                BigInt("0xBB434A2DEE7269E7") /*  240 */, BigInt("0x78CB67ECF931FA38") /*  241 */,
                BigInt("0xF33B0372323BBF9C") /*  242 */, BigInt("0x52D66336FB279C74") /*  243 */,
                BigInt("0x505F33AC0AFB4EAA") /*  244 */, BigInt("0xE8A5CD99A2CCE187") /*  245 */,
                BigInt("0x534974801E2D30BB") /*  246 */, BigInt("0x8D2D5711D5876D90") /*  247 */,
                BigInt("0x1F1A412891BC038E") /*  248 */, BigInt("0xD6E2E71D82E56648") /*  249 */,
                BigInt("0x74036C3A497732B7") /*  250 */, BigInt("0x89B67ED96361F5AB") /*  251 */,
                BigInt("0xFFED95D8F1EA02A2") /*  252 */, BigInt("0xE72B3BD61464D43D") /*  253 */,
                BigInt("0xA6300F170BDC4820") /*  254 */, BigInt("0xEBC18760ED78A77A") /*  255 */
            ];
            t2 = [
                BigInt("0xE6A6BE5A05A12138") /*  256 */, BigInt("0xB5A122A5B4F87C98") /*  257 */,
                BigInt("0x563C6089140B6990") /*  258 */, BigInt("0x4C46CB2E391F5DD5") /*  259 */,
                BigInt("0xD932ADDBC9B79434") /*  260 */, BigInt("0x08EA70E42015AFF5") /*  261 */,
                BigInt("0xD765A6673E478CF1") /*  262 */, BigInt("0xC4FB757EAB278D99") /*  263 */,
                BigInt("0xDF11C6862D6E0692") /*  264 */, BigInt("0xDDEB84F10D7F3B16") /*  265 */,
                BigInt("0x6F2EF604A665EA04") /*  266 */, BigInt("0x4A8E0F0FF0E0DFB3") /*  267 */,
                BigInt("0xA5EDEEF83DBCBA51") /*  268 */, BigInt("0xFC4F0A2A0EA4371E") /*  269 */,
                BigInt("0xE83E1DA85CB38429") /*  270 */, BigInt("0xDC8FF882BA1B1CE2") /*  271 */,
                BigInt("0xCD45505E8353E80D") /*  272 */, BigInt("0x18D19A00D4DB0717") /*  273 */,
                BigInt("0x34A0CFEDA5F38101") /*  274 */, BigInt("0x0BE77E518887CAF2") /*  275 */,
                BigInt("0x1E341438B3C45136") /*  276 */, BigInt("0xE05797F49089CCF9") /*  277 */,
                BigInt("0xFFD23F9DF2591D14") /*  278 */, BigInt("0x543DDA228595C5CD") /*  279 */,
                BigInt("0x661F81FD99052A33") /*  280 */, BigInt("0x8736E641DB0F7B76") /*  281 */,
                BigInt("0x15227725418E5307") /*  282 */, BigInt("0xE25F7F46162EB2FA") /*  283 */,
                BigInt("0x48A8B2126C13D9FE") /*  284 */, BigInt("0xAFDC541792E76EEA") /*  285 */,
                BigInt("0x03D912BFC6D1898F") /*  286 */, BigInt("0x31B1AAFA1B83F51B") /*  287 */,
                BigInt("0xF1AC2796E42AB7D9") /*  288 */, BigInt("0x40A3A7D7FCD2EBAC") /*  289 */,
                BigInt("0x1056136D0AFBBCC5") /*  290 */, BigInt("0x7889E1DD9A6D0C85") /*  291 */,
                BigInt("0xD33525782A7974AA") /*  292 */, BigInt("0xA7E25D09078AC09B") /*  293 */,
                BigInt("0xBD4138B3EAC6EDD0") /*  294 */, BigInt("0x920ABFBE71EB9E70") /*  295 */,
                BigInt("0xA2A5D0F54FC2625C") /*  296 */, BigInt("0xC054E36B0B1290A3") /*  297 */,
                BigInt("0xF6DD59FF62FE932B") /*  298 */, BigInt("0x3537354511A8AC7D") /*  299 */,
                BigInt("0xCA845E9172FADCD4") /*  300 */, BigInt("0x84F82B60329D20DC") /*  301 */,
                BigInt("0x79C62CE1CD672F18") /*  302 */, BigInt("0x8B09A2ADD124642C") /*  303 */,
                BigInt("0xD0C1E96A19D9E726") /*  304 */, BigInt("0x5A786A9B4BA9500C") /*  305 */,
                BigInt("0x0E020336634C43F3") /*  306 */, BigInt("0xC17B474AEB66D822") /*  307 */,
                BigInt("0x6A731AE3EC9BAAC2") /*  308 */, BigInt("0x8226667AE0840258") /*  309 */,
                BigInt("0x67D4567691CAECA5") /*  310 */, BigInt("0x1D94155C4875ADB5") /*  311 */,
                BigInt("0x6D00FD985B813FDF") /*  312 */, BigInt("0x51286EFCB774CD06") /*  313 */,
                BigInt("0x5E8834471FA744AF") /*  314 */, BigInt("0xF72CA0AEE761AE2E") /*  315 */,
                BigInt("0xBE40E4CDAEE8E09A") /*  316 */, BigInt("0xE9970BBB5118F665") /*  317 */,
                BigInt("0x726E4BEB33DF1964") /*  318 */, BigInt("0x703B000729199762") /*  319 */,
                BigInt("0x4631D816F5EF30A7") /*  320 */, BigInt("0xB880B5B51504A6BE") /*  321 */,
                BigInt("0x641793C37ED84B6C") /*  322 */, BigInt("0x7B21ED77F6E97D96") /*  323 */,
                BigInt("0x776306312EF96B73") /*  324 */, BigInt("0xAE528948E86FF3F4") /*  325 */,
                BigInt("0x53DBD7F286A3F8F8") /*  326 */, BigInt("0x16CADCE74CFC1063") /*  327 */,
                BigInt("0x005C19BDFA52C6DD") /*  328 */, BigInt("0x68868F5D64D46AD3") /*  329 */,
                BigInt("0x3A9D512CCF1E186A") /*  330 */, BigInt("0x367E62C2385660AE") /*  331 */,
                BigInt("0xE359E7EA77DCB1D7") /*  332 */, BigInt("0x526C0773749ABE6E") /*  333 */,
                BigInt("0x735AE5F9D09F734B") /*  334 */, BigInt("0x493FC7CC8A558BA8") /*  335 */,
                BigInt("0xB0B9C1533041AB45") /*  336 */, BigInt("0x321958BA470A59BD") /*  337 */,
                BigInt("0x852DB00B5F46C393") /*  338 */, BigInt("0x91209B2BD336B0E5") /*  339 */,
                BigInt("0x6E604F7D659EF19F") /*  340 */, BigInt("0xB99A8AE2782CCB24") /*  341 */,
                BigInt("0xCCF52AB6C814C4C7") /*  342 */, BigInt("0x4727D9AFBE11727B") /*  343 */,
                BigInt("0x7E950D0C0121B34D") /*  344 */, BigInt("0x756F435670AD471F") /*  345 */,
                BigInt("0xF5ADD442615A6849") /*  346 */, BigInt("0x4E87E09980B9957A") /*  347 */,
                BigInt("0x2ACFA1DF50AEE355") /*  348 */, BigInt("0xD898263AFD2FD556") /*  349 */,
                BigInt("0xC8F4924DD80C8FD6") /*  350 */, BigInt("0xCF99CA3D754A173A") /*  351 */,
                BigInt("0xFE477BACAF91BF3C") /*  352 */, BigInt("0xED5371F6D690C12D") /*  353 */,
                BigInt("0x831A5C285E687094") /*  354 */, BigInt("0xC5D3C90A3708A0A4") /*  355 */,
                BigInt("0x0F7F903717D06580") /*  356 */, BigInt("0x19F9BB13B8FDF27F") /*  357 */,
                BigInt("0xB1BD6F1B4D502843") /*  358 */, BigInt("0x1C761BA38FFF4012") /*  359 */,
                BigInt("0x0D1530C4E2E21F3B") /*  360 */, BigInt("0x8943CE69A7372C8A") /*  361 */,
                BigInt("0xE5184E11FEB5CE66") /*  362 */, BigInt("0x618BDB80BD736621") /*  363 */,
                BigInt("0x7D29BAD68B574D0B") /*  364 */, BigInt("0x81BB613E25E6FE5B") /*  365 */,
                BigInt("0x071C9C10BC07913F") /*  366 */, BigInt("0xC7BEEB7909AC2D97") /*  367 */,
                BigInt("0xC3E58D353BC5D757") /*  368 */, BigInt("0xEB017892F38F61E8") /*  369 */,
                BigInt("0xD4EFFB9C9B1CC21A") /*  370 */, BigInt("0x99727D26F494F7AB") /*  371 */,
                BigInt("0xA3E063A2956B3E03") /*  372 */, BigInt("0x9D4A8B9A4AA09C30") /*  373 */,
                BigInt("0x3F6AB7D500090FB4") /*  374 */, BigInt("0x9CC0F2A057268AC0") /*  375 */,
                BigInt("0x3DEE9D2DEDBF42D1") /*  376 */, BigInt("0x330F49C87960A972") /*  377 */,
                BigInt("0xC6B2720287421B41") /*  378 */, BigInt("0x0AC59EC07C00369C") /*  379 */,
                BigInt("0xEF4EAC49CB353425") /*  380 */, BigInt("0xF450244EEF0129D8") /*  381 */,
                BigInt("0x8ACC46E5CAF4DEB6") /*  382 */, BigInt("0x2FFEAB63989263F7") /*  383 */,
                BigInt("0x8F7CB9FE5D7A4578") /*  384 */, BigInt("0x5BD8F7644E634635") /*  385 */,
                BigInt("0x427A7315BF2DC900") /*  386 */, BigInt("0x17D0C4AA2125261C") /*  387 */,
                BigInt("0x3992486C93518E50") /*  388 */, BigInt("0xB4CBFEE0A2D7D4C3") /*  389 */,
                BigInt("0x7C75D6202C5DDD8D") /*  390 */, BigInt("0xDBC295D8E35B6C61") /*  391 */,
                BigInt("0x60B369D302032B19") /*  392 */, BigInt("0xCE42685FDCE44132") /*  393 */,
                BigInt("0x06F3DDB9DDF65610") /*  394 */, BigInt("0x8EA4D21DB5E148F0") /*  395 */,
                BigInt("0x20B0FCE62FCD496F") /*  396 */, BigInt("0x2C1B912358B0EE31") /*  397 */,
                BigInt("0xB28317B818F5A308") /*  398 */, BigInt("0xA89C1E189CA6D2CF") /*  399 */,
                BigInt("0x0C6B18576AAADBC8") /*  400 */, BigInt("0xB65DEAA91299FAE3") /*  401 */,
                BigInt("0xFB2B794B7F1027E7") /*  402 */, BigInt("0x04E4317F443B5BEB") /*  403 */,
                BigInt("0x4B852D325939D0A6") /*  404 */, BigInt("0xD5AE6BEEFB207FFC") /*  405 */,
                BigInt("0x309682B281C7D374") /*  406 */, BigInt("0xBAE309A194C3B475") /*  407 */,
                BigInt("0x8CC3F97B13B49F05") /*  408 */, BigInt("0x98A9422FF8293967") /*  409 */,
                BigInt("0x244B16B01076FF7C") /*  410 */, BigInt("0xF8BF571C663D67EE") /*  411 */,
                BigInt("0x1F0D6758EEE30DA1") /*  412 */, BigInt("0xC9B611D97ADEB9B7") /*  413 */,
                BigInt("0xB7AFD5887B6C57A2") /*  414 */, BigInt("0x6290AE846B984FE1") /*  415 */,
                BigInt("0x94DF4CDEACC1A5FD") /*  416 */, BigInt("0x058A5BD1C5483AFF") /*  417 */,
                BigInt("0x63166CC142BA3C37") /*  418 */, BigInt("0x8DB8526EB2F76F40") /*  419 */,
                BigInt("0xE10880036F0D6D4E") /*  420 */, BigInt("0x9E0523C9971D311D") /*  421 */,
                BigInt("0x45EC2824CC7CD691") /*  422 */, BigInt("0x575B8359E62382C9") /*  423 */,
                BigInt("0xFA9E400DC4889995") /*  424 */, BigInt("0xD1823ECB45721568") /*  425 */,
                BigInt("0xDAFD983B8206082F") /*  426 */, BigInt("0xAA7D29082386A8CB") /*  427 */,
                BigInt("0x269FCD4403B87588") /*  428 */, BigInt("0x1B91F5F728BDD1E0") /*  429 */,
                BigInt("0xE4669F39040201F6") /*  430 */, BigInt("0x7A1D7C218CF04ADE") /*  431 */,
                BigInt("0x65623C29D79CE5CE") /*  432 */, BigInt("0x2368449096C00BB1") /*  433 */,
                BigInt("0xAB9BF1879DA503BA") /*  434 */, BigInt("0xBC23ECB1A458058E") /*  435 */,
                BigInt("0x9A58DF01BB401ECC") /*  436 */, BigInt("0xA070E868A85F143D") /*  437 */,
                BigInt("0x4FF188307DF2239E") /*  438 */, BigInt("0x14D565B41A641183") /*  439 */,
                BigInt("0xEE13337452701602") /*  440 */, BigInt("0x950E3DCF3F285E09") /*  441 */,
                BigInt("0x59930254B9C80953") /*  442 */, BigInt("0x3BF299408930DA6D") /*  443 */,
                BigInt("0xA955943F53691387") /*  444 */, BigInt("0xA15EDECAA9CB8784") /*  445 */,
                BigInt("0x29142127352BE9A0") /*  446 */, BigInt("0x76F0371FFF4E7AFB") /*  447 */,
                BigInt("0x0239F450274F2228") /*  448 */, BigInt("0xBB073AF01D5E868B") /*  449 */,
                BigInt("0xBFC80571C10E96C1") /*  450 */, BigInt("0xD267088568222E23") /*  451 */,
                BigInt("0x9671A3D48E80B5B0") /*  452 */, BigInt("0x55B5D38AE193BB81") /*  453 */,
                BigInt("0x693AE2D0A18B04B8") /*  454 */, BigInt("0x5C48B4ECADD5335F") /*  455 */,
                BigInt("0xFD743B194916A1CA") /*  456 */, BigInt("0x2577018134BE98C4") /*  457 */,
                BigInt("0xE77987E83C54A4AD") /*  458 */, BigInt("0x28E11014DA33E1B9") /*  459 */,
                BigInt("0x270CC59E226AA213") /*  460 */, BigInt("0x71495F756D1A5F60") /*  461 */,
                BigInt("0x9BE853FB60AFEF77") /*  462 */, BigInt("0xADC786A7F7443DBF") /*  463 */,
                BigInt("0x0904456173B29A82") /*  464 */, BigInt("0x58BC7A66C232BD5E") /*  465 */,
                BigInt("0xF306558C673AC8B2") /*  466 */, BigInt("0x41F639C6B6C9772A") /*  467 */,
                BigInt("0x216DEFE99FDA35DA") /*  468 */, BigInt("0x11640CC71C7BE615") /*  469 */,
                BigInt("0x93C43694565C5527") /*  470 */, BigInt("0xEA038E6246777839") /*  471 */,
                BigInt("0xF9ABF3CE5A3E2469") /*  472 */, BigInt("0x741E768D0FD312D2") /*  473 */,
                BigInt("0x0144B883CED652C6") /*  474 */, BigInt("0xC20B5A5BA33F8552") /*  475 */,
                BigInt("0x1AE69633C3435A9D") /*  476 */, BigInt("0x97A28CA4088CFDEC") /*  477 */,
                BigInt("0x8824A43C1E96F420") /*  478 */, BigInt("0x37612FA66EEEA746") /*  479 */,
                BigInt("0x6B4CB165F9CF0E5A") /*  480 */, BigInt("0x43AA1C06A0ABFB4A") /*  481 */,
                BigInt("0x7F4DC26FF162796B") /*  482 */, BigInt("0x6CBACC8E54ED9B0F") /*  483 */,
                BigInt("0xA6B7FFEFD2BB253E") /*  484 */, BigInt("0x2E25BC95B0A29D4F") /*  485 */,
                BigInt("0x86D6A58BDEF1388C") /*  486 */, BigInt("0xDED74AC576B6F054") /*  487 */,
                BigInt("0x8030BDBC2B45805D") /*  488 */, BigInt("0x3C81AF70E94D9289") /*  489 */,
                BigInt("0x3EFF6DDA9E3100DB") /*  490 */, BigInt("0xB38DC39FDFCC8847") /*  491 */,
                BigInt("0x123885528D17B87E") /*  492 */, BigInt("0xF2DA0ED240B1B642") /*  493 */,
                BigInt("0x44CEFADCD54BF9A9") /*  494 */, BigInt("0x1312200E433C7EE6") /*  495 */,
                BigInt("0x9FFCC84F3A78C748") /*  496 */, BigInt("0xF0CD1F72248576BB") /*  497 */,
                BigInt("0xEC6974053638CFE4") /*  498 */, BigInt("0x2BA7B67C0CEC4E4C") /*  499 */,
                BigInt("0xAC2F4DF3E5CE32ED") /*  500 */, BigInt("0xCB33D14326EA4C11") /*  501 */,
                BigInt("0xA4E9044CC77E58BC") /*  502 */, BigInt("0x5F513293D934FCEF") /*  503 */,
                BigInt("0x5DC9645506E55444") /*  504 */, BigInt("0x50DE418F317DE40A") /*  505 */,
                BigInt("0x388CB31A69DDE259") /*  506 */, BigInt("0x2DB4A83455820A86") /*  507 */,
                BigInt("0x9010A91E84711AE9") /*  508 */, BigInt("0x4DF7F0B7B1498371") /*  509 */,
                BigInt("0xD62A2EABC0977179") /*  510 */, BigInt("0x22FAC097AA8D5C0E") /*  511 */,
            ];
            t3 = [
                BigInt("0xF49FCC2FF1DAF39B") /*  512 */, BigInt("0x487FD5C66FF29281") /*  513 */,
                BigInt("0xE8A30667FCDCA83F") /*  514 */, BigInt("0x2C9B4BE3D2FCCE63") /*  515 */,
                BigInt("0xDA3FF74B93FBBBC2") /*  516 */, BigInt("0x2FA165D2FE70BA66") /*  517 */,
                BigInt("0xA103E279970E93D4") /*  518 */, BigInt("0xBECDEC77B0E45E71") /*  519 */,
                BigInt("0xCFB41E723985E497") /*  520 */, BigInt("0xB70AAA025EF75017") /*  521 */,
                BigInt("0xD42309F03840B8E0") /*  522 */, BigInt("0x8EFC1AD035898579") /*  523 */,
                BigInt("0x96C6920BE2B2ABC5") /*  524 */, BigInt("0x66AF4163375A9172") /*  525 */,
                BigInt("0x2174ABDCCA7127FB") /*  526 */, BigInt("0xB33CCEA64A72FF41") /*  527 */,
                BigInt("0xF04A4933083066A5") /*  528 */, BigInt("0x8D970ACDD7289AF5") /*  529 */,
                BigInt("0x8F96E8E031C8C25E") /*  530 */, BigInt("0xF3FEC02276875D47") /*  531 */,
                BigInt("0xEC7BF310056190DD") /*  532 */, BigInt("0xF5ADB0AEBB0F1491") /*  533 */,
                BigInt("0x9B50F8850FD58892") /*  534 */, BigInt("0x4975488358B74DE8") /*  535 */,
                BigInt("0xA3354FF691531C61") /*  536 */, BigInt("0x0702BBE481D2C6EE") /*  537 */,
                BigInt("0x89FB24057DEDED98") /*  538 */, BigInt("0xAC3075138596E902") /*  539 */,
                BigInt("0x1D2D3580172772ED") /*  540 */, BigInt("0xEB738FC28E6BC30D") /*  541 */,
                BigInt("0x5854EF8F63044326") /*  542 */, BigInt("0x9E5C52325ADD3BBE") /*  543 */,
                BigInt("0x90AA53CF325C4623") /*  544 */, BigInt("0xC1D24D51349DD067") /*  545 */,
                BigInt("0x2051CFEEA69EA624") /*  546 */, BigInt("0x13220F0A862E7E4F") /*  547 */,
                BigInt("0xCE39399404E04864") /*  548 */, BigInt("0xD9C42CA47086FCB7") /*  549 */,
                BigInt("0x685AD2238A03E7CC") /*  550 */, BigInt("0x066484B2AB2FF1DB") /*  551 */,
                BigInt("0xFE9D5D70EFBF79EC") /*  552 */, BigInt("0x5B13B9DD9C481854") /*  553 */,
                BigInt("0x15F0D475ED1509AD") /*  554 */, BigInt("0x0BEBCD060EC79851") /*  555 */,
                BigInt("0xD58C6791183AB7F8") /*  556 */, BigInt("0xD1187C5052F3EEE4") /*  557 */,
                BigInt("0xC95D1192E54E82FF") /*  558 */, BigInt("0x86EEA14CB9AC6CA2") /*  559 */,
                BigInt("0x3485BEB153677D5D") /*  560 */, BigInt("0xDD191D781F8C492A") /*  561 */,
                BigInt("0xF60866BAA784EBF9") /*  562 */, BigInt("0x518F643BA2D08C74") /*  563 */,
                BigInt("0x8852E956E1087C22") /*  564 */, BigInt("0xA768CB8DC410AE8D") /*  565 */,
                BigInt("0x38047726BFEC8E1A") /*  566 */, BigInt("0xA67738B4CD3B45AA") /*  567 */,
                BigInt("0xAD16691CEC0DDE19") /*  568 */, BigInt("0xC6D4319380462E07") /*  569 */,
                BigInt("0xC5A5876D0BA61938") /*  570 */, BigInt("0x16B9FA1FA58FD840") /*  571 */,
                BigInt("0x188AB1173CA74F18") /*  572 */, BigInt("0xABDA2F98C99C021F") /*  573 */,
                BigInt("0x3E0580AB134AE816") /*  574 */, BigInt("0x5F3B05B773645ABB") /*  575 */,
                BigInt("0x2501A2BE5575F2F6") /*  576 */, BigInt("0x1B2F74004E7E8BA9") /*  577 */,
                BigInt("0x1CD7580371E8D953") /*  578 */, BigInt("0x7F6ED89562764E30") /*  579 */,
                BigInt("0xB15926FF596F003D") /*  580 */, BigInt("0x9F65293DA8C5D6B9") /*  581 */,
                BigInt("0x6ECEF04DD690F84C") /*  582 */, BigInt("0x4782275FFF33AF88") /*  583 */,
                BigInt("0xE41433083F820801") /*  584 */, BigInt("0xFD0DFE409A1AF9B5") /*  585 */,
                BigInt("0x4325A3342CDB396B") /*  586 */, BigInt("0x8AE77E62B301B252") /*  587 */,
                BigInt("0xC36F9E9F6655615A") /*  588 */, BigInt("0x85455A2D92D32C09") /*  589 */,
                BigInt("0xF2C7DEA949477485") /*  590 */, BigInt("0x63CFB4C133A39EBA") /*  591 */,
                BigInt("0x83B040CC6EBC5462") /*  592 */, BigInt("0x3B9454C8FDB326B0") /*  593 */,
                BigInt("0x56F56A9E87FFD78C") /*  594 */, BigInt("0x2DC2940D99F42BC6") /*  595 */,
                BigInt("0x98F7DF096B096E2D") /*  596 */, BigInt("0x19A6E01E3AD852BF") /*  597 */,
                BigInt("0x42A99CCBDBD4B40B") /*  598 */, BigInt("0xA59998AF45E9C559") /*  599 */,
                BigInt("0x366295E807D93186") /*  600 */, BigInt("0x6B48181BFAA1F773") /*  601 */,
                BigInt("0x1FEC57E2157A0A1D") /*  602 */, BigInt("0x4667446AF6201AD5") /*  603 */,
                BigInt("0xE615EBCACFB0F075") /*  604 */, BigInt("0xB8F31F4F68290778") /*  605 */,
                BigInt("0x22713ED6CE22D11E") /*  606 */, BigInt("0x3057C1A72EC3C93B") /*  607 */,
                BigInt("0xCB46ACC37C3F1F2F") /*  608 */, BigInt("0xDBB893FD02AAF50E") /*  609 */,
                BigInt("0x331FD92E600B9FCF") /*  610 */, BigInt("0xA498F96148EA3AD6") /*  611 */,
                BigInt("0xA8D8426E8B6A83EA") /*  612 */, BigInt("0xA089B274B7735CDC") /*  613 */,
                BigInt("0x87F6B3731E524A11") /*  614 */, BigInt("0x118808E5CBC96749") /*  615 */,
                BigInt("0x9906E4C7B19BD394") /*  616 */, BigInt("0xAFED7F7E9B24A20C") /*  617 */,
                BigInt("0x6509EADEEB3644A7") /*  618 */, BigInt("0x6C1EF1D3E8EF0EDE") /*  619 */,
                BigInt("0xB9C97D43E9798FB4") /*  620 */, BigInt("0xA2F2D784740C28A3") /*  621 */,
                BigInt("0x7B8496476197566F") /*  622 */, BigInt("0x7A5BE3E6B65F069D") /*  623 */,
                BigInt("0xF96330ED78BE6F10") /*  624 */, BigInt("0xEEE60DE77A076A15") /*  625 */,
                BigInt("0x2B4BEE4AA08B9BD0") /*  626 */, BigInt("0x6A56A63EC7B8894E") /*  627 */,
                BigInt("0x02121359BA34FEF4") /*  628 */, BigInt("0x4CBF99F8283703FC") /*  629 */,
                BigInt("0x398071350CAF30C8") /*  630 */, BigInt("0xD0A77A89F017687A") /*  631 */,
                BigInt("0xF1C1A9EB9E423569") /*  632 */, BigInt("0x8C7976282DEE8199") /*  633 */,
                BigInt("0x5D1737A5DD1F7ABD") /*  634 */, BigInt("0x4F53433C09A9FA80") /*  635 */,
                BigInt("0xFA8B0C53DF7CA1D9") /*  636 */, BigInt("0x3FD9DCBC886CCB77") /*  637 */,
                BigInt("0xC040917CA91B4720") /*  638 */, BigInt("0x7DD00142F9D1DCDF") /*  639 */,
                BigInt("0x8476FC1D4F387B58") /*  640 */, BigInt("0x23F8E7C5F3316503") /*  641 */,
                BigInt("0x032A2244E7E37339") /*  642 */, BigInt("0x5C87A5D750F5A74B") /*  643 */,
                BigInt("0x082B4CC43698992E") /*  644 */, BigInt("0xDF917BECB858F63C") /*  645 */,
                BigInt("0x3270B8FC5BF86DDA") /*  646 */, BigInt("0x10AE72BB29B5DD76") /*  647 */,
                BigInt("0x576AC94E7700362B") /*  648 */, BigInt("0x1AD112DAC61EFB8F") /*  649 */,
                BigInt("0x691BC30EC5FAA427") /*  650 */, BigInt("0xFF246311CC327143") /*  651 */,
                BigInt("0x3142368E30E53206") /*  652 */, BigInt("0x71380E31E02CA396") /*  653 */,
                BigInt("0x958D5C960AAD76F1") /*  654 */, BigInt("0xF8D6F430C16DA536") /*  655 */,
                BigInt("0xC8FFD13F1BE7E1D2") /*  656 */, BigInt("0x7578AE66004DDBE1") /*  657 */,
                BigInt("0x05833F01067BE646") /*  658 */, BigInt("0xBB34B5AD3BFE586D") /*  659 */,
                BigInt("0x095F34C9A12B97F0") /*  660 */, BigInt("0x247AB64525D60CA8") /*  661 */,
                BigInt("0xDCDBC6F3017477D1") /*  662 */, BigInt("0x4A2E14D4DECAD24D") /*  663 */,
                BigInt("0xBDB5E6D9BE0A1EEB") /*  664 */, BigInt("0x2A7E70F7794301AB") /*  665 */,
                BigInt("0xDEF42D8A270540FD") /*  666 */, BigInt("0x01078EC0A34C22C1") /*  667 */,
                BigInt("0xE5DE511AF4C16387") /*  668 */, BigInt("0x7EBB3A52BD9A330A") /*  669 */,
                BigInt("0x77697857AA7D6435") /*  670 */, BigInt("0x004E831603AE4C32") /*  671 */,
                BigInt("0xE7A21020AD78E312") /*  672 */, BigInt("0x9D41A70C6AB420F2") /*  673 */,
                BigInt("0x28E06C18EA1141E6") /*  674 */, BigInt("0xD2B28CBD984F6B28") /*  675 */,
                BigInt("0x26B75F6C446E9D83") /*  676 */, BigInt("0xBA47568C4D418D7F") /*  677 */,
                BigInt("0xD80BADBFE6183D8E") /*  678 */, BigInt("0x0E206D7F5F166044") /*  679 */,
                BigInt("0xE258A43911CBCA3E") /*  680 */, BigInt("0x723A1746B21DC0BC") /*  681 */,
                BigInt("0xC7CAA854F5D7CDD3") /*  682 */, BigInt("0x7CAC32883D261D9C") /*  683 */,
                BigInt("0x7690C26423BA942C") /*  684 */, BigInt("0x17E55524478042B8") /*  685 */,
                BigInt("0xE0BE477656A2389F") /*  686 */, BigInt("0x4D289B5E67AB2DA0") /*  687 */,
                BigInt("0x44862B9C8FBBFD31") /*  688 */, BigInt("0xB47CC8049D141365") /*  689 */,
                BigInt("0x822C1B362B91C793") /*  690 */, BigInt("0x4EB14655FB13DFD8") /*  691 */,
                BigInt("0x1ECBBA0714E2A97B") /*  692 */, BigInt("0x6143459D5CDE5F14") /*  693 */,
                BigInt("0x53A8FBF1D5F0AC89") /*  694 */, BigInt("0x97EA04D81C5E5B00") /*  695 */,
                BigInt("0x622181A8D4FDB3F3") /*  696 */, BigInt("0xE9BCD341572A1208") /*  697 */,
                BigInt("0x1411258643CCE58A") /*  698 */, BigInt("0x9144C5FEA4C6E0A4") /*  699 */,
                BigInt("0x0D33D06565CF620F") /*  700 */, BigInt("0x54A48D489F219CA1") /*  701 */,
                BigInt("0xC43E5EAC6D63C821") /*  702 */, BigInt("0xA9728B3A72770DAF") /*  703 */,
                BigInt("0xD7934E7B20DF87EF") /*  704 */, BigInt("0xE35503B61A3E86E5") /*  705 */,
                BigInt("0xCAE321FBC819D504") /*  706 */, BigInt("0x129A50B3AC60BFA6") /*  707 */,
                BigInt("0xCD5E68EA7E9FB6C3") /*  708 */, BigInt("0xB01C90199483B1C7") /*  709 */,
                BigInt("0x3DE93CD5C295376C") /*  710 */, BigInt("0xAED52EDF2AB9AD13") /*  711 */,
                BigInt("0x2E60F512C0A07884") /*  712 */, BigInt("0xBC3D86A3E36210C9") /*  713 */,
                BigInt("0x35269D9B163951CE") /*  714 */, BigInt("0x0C7D6E2AD0CDB5FA") /*  715 */,
                BigInt("0x59E86297D87F5733") /*  716 */, BigInt("0x298EF221898DB0E7") /*  717 */,
                BigInt("0x55000029D1A5AA7E") /*  718 */, BigInt("0x8BC08AE1B5061B45") /*  719 */,
                BigInt("0xC2C31C2B6C92703A") /*  720 */, BigInt("0x94CC596BAF25EF42") /*  721 */,
                BigInt("0x0A1D73DB22540456") /*  722 */, BigInt("0x04B6A0F9D9C4179A") /*  723 */,
                BigInt("0xEFFDAFA2AE3D3C60") /*  724 */, BigInt("0xF7C8075BB49496C4") /*  725 */,
                BigInt("0x9CC5C7141D1CD4E3") /*  726 */, BigInt("0x78BD1638218E5534") /*  727 */,
                BigInt("0xB2F11568F850246A") /*  728 */, BigInt("0xEDFABCFA9502BC29") /*  729 */,
                BigInt("0x796CE5F2DA23051B") /*  730 */, BigInt("0xAAE128B0DC93537C") /*  731 */,
                BigInt("0x3A493DA0EE4B29AE") /*  732 */, BigInt("0xB5DF6B2C416895D7") /*  733 */,
                BigInt("0xFCABBD25122D7F37") /*  734 */, BigInt("0x70810B58105DC4B1") /*  735 */,
                BigInt("0xE10FDD37F7882A90") /*  736 */, BigInt("0x524DCAB5518A3F5C") /*  737 */,
                BigInt("0x3C9E85878451255B") /*  738 */, BigInt("0x4029828119BD34E2") /*  739 */,
                BigInt("0x74A05B6F5D3CECCB") /*  740 */, BigInt("0xB610021542E13ECA") /*  741 */,
                BigInt("0x0FF979D12F59E2AC") /*  742 */, BigInt("0x6037DA27E4F9CC50") /*  743 */,
                BigInt("0x5E92975A0DF1847D") /*  744 */, BigInt("0xD66DE190D3E623FE") /*  745 */,
                BigInt("0x5032D6B87B568048") /*  746 */, BigInt("0x9A36B7CE8235216E") /*  747 */,
                BigInt("0x80272A7A24F64B4A") /*  748 */, BigInt("0x93EFED8B8C6916F7") /*  749 */,
                BigInt("0x37DDBFF44CCE1555") /*  750 */, BigInt("0x4B95DB5D4B99BD25") /*  751 */,
                BigInt("0x92D3FDA169812FC0") /*  752 */, BigInt("0xFB1A4A9A90660BB6") /*  753 */,
                BigInt("0x730C196946A4B9B2") /*  754 */, BigInt("0x81E289AA7F49DA68") /*  755 */,
                BigInt("0x64669A0F83B1A05F") /*  756 */, BigInt("0x27B3FF7D9644F48B") /*  757 */,
                BigInt("0xCC6B615C8DB675B3") /*  758 */, BigInt("0x674F20B9BCEBBE95") /*  759 */,
                BigInt("0x6F31238275655982") /*  760 */, BigInt("0x5AE488713E45CF05") /*  761 */,
                BigInt("0xBF619F9954C21157") /*  762 */, BigInt("0xEABAC46040A8EAE9") /*  763 */,
                BigInt("0x454C6FE9F2C0C1CD") /*  764 */, BigInt("0x419CF6496412691C") /*  765 */,
                BigInt("0xD3DC3BEF265B0F70") /*  766 */, BigInt("0x6D0E60F5C3578A9E") /*  767 */,
            ];
            t4 = [
                BigInt("0x5B0E608526323C55") /*  768 */, BigInt("0x1A46C1A9FA1B59F5") /*  769 */,
                BigInt("0xA9E245A17C4C8FFA") /*  770 */, BigInt("0x65CA5159DB2955D7") /*  771 */,
                BigInt("0x05DB0A76CE35AFC2") /*  772 */, BigInt("0x81EAC77EA9113D45") /*  773 */,
                BigInt("0x528EF88AB6AC0A0D") /*  774 */, BigInt("0xA09EA253597BE3FF") /*  775 */,
                BigInt("0x430DDFB3AC48CD56") /*  776 */, BigInt("0xC4B3A67AF45CE46F") /*  777 */,
                BigInt("0x4ECECFD8FBE2D05E") /*  778 */, BigInt("0x3EF56F10B39935F0") /*  779 */,
                BigInt("0x0B22D6829CD619C6") /*  780 */, BigInt("0x17FD460A74DF2069") /*  781 */,
                BigInt("0x6CF8CC8E8510ED40") /*  782 */, BigInt("0xD6C824BF3A6ECAA7") /*  783 */,
                BigInt("0x61243D581A817049") /*  784 */, BigInt("0x048BACB6BBC163A2") /*  785 */,
                BigInt("0xD9A38AC27D44CC32") /*  786 */, BigInt("0x7FDDFF5BAAF410AB") /*  787 */,
                BigInt("0xAD6D495AA804824B") /*  788 */, BigInt("0xE1A6A74F2D8C9F94") /*  789 */,
                BigInt("0xD4F7851235DEE8E3") /*  790 */, BigInt("0xFD4B7F886540D893") /*  791 */,
                BigInt("0x247C20042AA4BFDA") /*  792 */, BigInt("0x096EA1C517D1327C") /*  793 */,
                BigInt("0xD56966B4361A6685") /*  794 */, BigInt("0x277DA5C31221057D") /*  795 */,
                BigInt("0x94D59893A43ACFF7") /*  796 */, BigInt("0x64F0C51CCDC02281") /*  797 */,
                BigInt("0x3D33BCC4FF6189DB") /*  798 */, BigInt("0xE005CB184CE66AF1") /*  799 */,
                BigInt("0xFF5CCD1D1DB99BEA") /*  800 */, BigInt("0xB0B854A7FE42980F") /*  801 */,
                BigInt("0x7BD46A6A718D4B9F") /*  802 */, BigInt("0xD10FA8CC22A5FD8C") /*  803 */,
                BigInt("0xD31484952BE4BD31") /*  804 */, BigInt("0xC7FA975FCB243847") /*  805 */,
                BigInt("0x4886ED1E5846C407") /*  806 */, BigInt("0x28CDDB791EB70B04") /*  807 */,
                BigInt("0xC2B00BE2F573417F") /*  808 */, BigInt("0x5C9590452180F877") /*  809 */,
                BigInt("0x7A6BDDFFF370EB00") /*  810 */, BigInt("0xCE509E38D6D9D6A4") /*  811 */,
                BigInt("0xEBEB0F00647FA702") /*  812 */, BigInt("0x1DCC06CF76606F06") /*  813 */,
                BigInt("0xE4D9F28BA286FF0A") /*  814 */, BigInt("0xD85A305DC918C262") /*  815 */,
                BigInt("0x475B1D8732225F54") /*  816 */, BigInt("0x2D4FB51668CCB5FE") /*  817 */,
                BigInt("0xA679B9D9D72BBA20") /*  818 */, BigInt("0x53841C0D912D43A5") /*  819 */,
                BigInt("0x3B7EAA48BF12A4E8") /*  820 */, BigInt("0x781E0E47F22F1DDF") /*  821 */,
                BigInt("0xEFF20CE60AB50973") /*  822 */, BigInt("0x20D261D19DFFB742") /*  823 */,
                BigInt("0x16A12B03062A2E39") /*  824 */, BigInt("0x1960EB2239650495") /*  825 */,
                BigInt("0x251C16FED50EB8B8") /*  826 */, BigInt("0x9AC0C330F826016E") /*  827 */,
                BigInt("0xED152665953E7671") /*  828 */, BigInt("0x02D63194A6369570") /*  829 */,
                BigInt("0x5074F08394B1C987") /*  830 */, BigInt("0x70BA598C90B25CE1") /*  831 */,
                BigInt("0x794A15810B9742F6") /*  832 */, BigInt("0x0D5925E9FCAF8C6C") /*  833 */,
                BigInt("0x3067716CD868744E") /*  834 */, BigInt("0x910AB077E8D7731B") /*  835 */,
                BigInt("0x6A61BBDB5AC42F61") /*  836 */, BigInt("0x93513EFBF0851567") /*  837 */,
                BigInt("0xF494724B9E83E9D5") /*  838 */, BigInt("0xE887E1985C09648D") /*  839 */,
                BigInt("0x34B1D3C675370CFD") /*  840 */, BigInt("0xDC35E433BC0D255D") /*  841 */,
                BigInt("0xD0AAB84234131BE0") /*  842 */, BigInt("0x08042A50B48B7EAF") /*  843 */,
                BigInt("0x9997C4EE44A3AB35") /*  844 */, BigInt("0x829A7B49201799D0") /*  845 */,
                BigInt("0x263B8307B7C54441") /*  846 */, BigInt("0x752F95F4FD6A6CA6") /*  847 */,
                BigInt("0x927217402C08C6E5") /*  848 */, BigInt("0x2A8AB754A795D9EE") /*  849 */,
                BigInt("0xA442F7552F72943D") /*  850 */, BigInt("0x2C31334E19781208") /*  851 */,
                BigInt("0x4FA98D7CEAEE6291") /*  852 */, BigInt("0x55C3862F665DB309") /*  853 */,
                BigInt("0xBD0610175D53B1F3") /*  854 */, BigInt("0x46FE6CB840413F27") /*  855 */,
                BigInt("0x3FE03792DF0CFA59") /*  856 */, BigInt("0xCFE700372EB85E8F") /*  857 */,
                BigInt("0xA7BE29E7ADBCE118") /*  858 */, BigInt("0xE544EE5CDE8431DD") /*  859 */,
                BigInt("0x8A781B1B41F1873E") /*  860 */, BigInt("0xA5C94C78A0D2F0E7") /*  861 */,
                BigInt("0x39412E2877B60728") /*  862 */, BigInt("0xA1265EF3AFC9A62C") /*  863 */,
                BigInt("0xBCC2770C6A2506C5") /*  864 */, BigInt("0x3AB66DD5DCE1CE12") /*  865 */,
                BigInt("0xE65499D04A675B37") /*  866 */, BigInt("0x7D8F523481BFD216") /*  867 */,
                BigInt("0x0F6F64FCEC15F389") /*  868 */, BigInt("0x74EFBE618B5B13C8") /*  869 */,
                BigInt("0xACDC82B714273E1D") /*  870 */, BigInt("0xDD40BFE003199D17") /*  871 */,
                BigInt("0x37E99257E7E061F8") /*  872 */, BigInt("0xFA52626904775AAA") /*  873 */,
                BigInt("0x8BBBF63A463D56F9") /*  874 */, BigInt("0xF0013F1543A26E64") /*  875 */,
                BigInt("0xA8307E9F879EC898") /*  876 */, BigInt("0xCC4C27A4150177CC") /*  877 */,
                BigInt("0x1B432F2CCA1D3348") /*  878 */, BigInt("0xDE1D1F8F9F6FA013") /*  879 */,
                BigInt("0x606602A047A7DDD6") /*  880 */, BigInt("0xD237AB64CC1CB2C7") /*  881 */,
                BigInt("0x9B938E7225FCD1D3") /*  882 */, BigInt("0xEC4E03708E0FF476") /*  883 */,
                BigInt("0xFEB2FBDA3D03C12D") /*  884 */, BigInt("0xAE0BCED2EE43889A") /*  885 */,
                BigInt("0x22CB8923EBFB4F43") /*  886 */, BigInt("0x69360D013CF7396D") /*  887 */,
                BigInt("0x855E3602D2D4E022") /*  888 */, BigInt("0x073805BAD01F784C") /*  889 */,
                BigInt("0x33E17A133852F546") /*  890 */, BigInt("0xDF4874058AC7B638") /*  891 */,
                BigInt("0xBA92B29C678AA14A") /*  892 */, BigInt("0x0CE89FC76CFAADCD") /*  893 */,
                BigInt("0x5F9D4E0908339E34") /*  894 */, BigInt("0xF1AFE9291F5923B9") /*  895 */,
                BigInt("0x6E3480F60F4A265F") /*  896 */, BigInt("0xEEBF3A2AB29B841C") /*  897 */,
                BigInt("0xE21938A88F91B4AD") /*  898 */, BigInt("0x57DFEFF845C6D3C3") /*  899 */,
                BigInt("0x2F006B0BF62CAAF2") /*  900 */, BigInt("0x62F479EF6F75EE78") /*  901 */,
                BigInt("0x11A55AD41C8916A9") /*  902 */, BigInt("0xF229D29084FED453") /*  903 */,
                BigInt("0x42F1C27B16B000E6") /*  904 */, BigInt("0x2B1F76749823C074") /*  905 */,
                BigInt("0x4B76ECA3C2745360") /*  906 */, BigInt("0x8C98F463B91691BD") /*  907 */,
                BigInt("0x14BCC93CF1ADE66A") /*  908 */, BigInt("0x8885213E6D458397") /*  909 */,
                BigInt("0x8E177DF0274D4711") /*  910 */, BigInt("0xB49B73B5503F2951") /*  911 */,
                BigInt("0x10168168C3F96B6B") /*  912 */, BigInt("0x0E3D963B63CAB0AE") /*  913 */,
                BigInt("0x8DFC4B5655A1DB14") /*  914 */, BigInt("0xF789F1356E14DE5C") /*  915 */,
                BigInt("0x683E68AF4E51DAC1") /*  916 */, BigInt("0xC9A84F9D8D4B0FD9") /*  917 */,
                BigInt("0x3691E03F52A0F9D1") /*  918 */, BigInt("0x5ED86E46E1878E80") /*  919 */,
                BigInt("0x3C711A0E99D07150") /*  920 */, BigInt("0x5A0865B20C4E9310") /*  921 */,
                BigInt("0x56FBFC1FE4F0682E") /*  922 */, BigInt("0xEA8D5DE3105EDF9B") /*  923 */,
                BigInt("0x71ABFDB12379187A") /*  924 */, BigInt("0x2EB99DE1BEE77B9C") /*  925 */,
                BigInt("0x21ECC0EA33CF4523") /*  926 */, BigInt("0x59A4D7521805C7A1") /*  927 */,
                BigInt("0x3896F5EB56AE7C72") /*  928 */, BigInt("0xAA638F3DB18F75DC") /*  929 */,
                BigInt("0x9F39358DABE9808E") /*  930 */, BigInt("0xB7DEFA91C00B72AC") /*  931 */,
                BigInt("0x6B5541FD62492D92") /*  932 */, BigInt("0x6DC6DEE8F92E4D5B") /*  933 */,
                BigInt("0x353F57ABC4BEEA7E") /*  934 */, BigInt("0x735769D6DA5690CE") /*  935 */,
                BigInt("0x0A234AA642391484") /*  936 */, BigInt("0xF6F9508028F80D9D") /*  937 */,
                BigInt("0xB8E319A27AB3F215") /*  938 */, BigInt("0x31AD9C1151341A4D") /*  939 */,
                BigInt("0x773C22A57BEF5805") /*  940 */, BigInt("0x45C7561A07968633") /*  941 */,
                BigInt("0xF913DA9E249DBE36") /*  942 */, BigInt("0xDA652D9B78A64C68") /*  943 */,
                BigInt("0x4C27A97F3BC334EF") /*  944 */, BigInt("0x76621220E66B17F4") /*  945 */,
                BigInt("0x967743899ACD7D0B") /*  946 */, BigInt("0xF3EE5BCAE0ED6782") /*  947 */,
                BigInt("0x409F753600C879FC") /*  948 */, BigInt("0x06D09A39B5926DB6") /*  949 */,
                BigInt("0x6F83AEB0317AC588") /*  950 */, BigInt("0x01E6CA4A86381F21") /*  951 */,
                BigInt("0x66FF3462D19F3025") /*  952 */, BigInt("0x72207C24DDFD3BFB") /*  953 */,
                BigInt("0x4AF6B6D3E2ECE2EB") /*  954 */, BigInt("0x9C994DBEC7EA08DE") /*  955 */,
                BigInt("0x49ACE597B09A8BC4") /*  956 */, BigInt("0xB38C4766CF0797BA") /*  957 */,
                BigInt("0x131B9373C57C2A75") /*  958 */, BigInt("0xB1822CCE61931E58") /*  959 */,
                BigInt("0x9D7555B909BA1C0C") /*  960 */, BigInt("0x127FAFDD937D11D2") /*  961 */,
                BigInt("0x29DA3BADC66D92E4") /*  962 */, BigInt("0xA2C1D57154C2ECBC") /*  963 */,
                BigInt("0x58C5134D82F6FE24") /*  964 */, BigInt("0x1C3AE3515B62274F") /*  965 */,
                BigInt("0xE907C82E01CB8126") /*  966 */, BigInt("0xF8ED091913E37FCB") /*  967 */,
                BigInt("0x3249D8F9C80046C9") /*  968 */, BigInt("0x80CF9BEDE388FB63") /*  969 */,
                BigInt("0x1881539A116CF19E") /*  970 */, BigInt("0x5103F3F76BD52457") /*  971 */,
                BigInt("0x15B7E6F5AE47F7A8") /*  972 */, BigInt("0xDBD7C6DED47E9CCF") /*  973 */,
                BigInt("0x44E55C410228BB1A") /*  974 */, BigInt("0xB647D4255EDB4E99") /*  975 */,
                BigInt("0x5D11882BB8AAFC30") /*  976 */, BigInt("0xF5098BBB29D3212A") /*  977 */,
                BigInt("0x8FB5EA14E90296B3") /*  978 */, BigInt("0x677B942157DD025A") /*  979 */,
                BigInt("0xFB58E7C0A390ACB5") /*  980 */, BigInt("0x89D3674C83BD4A01") /*  981 */,
                BigInt("0x9E2DA4DF4BF3B93B") /*  982 */, BigInt("0xFCC41E328CAB4829") /*  983 */,
                BigInt("0x03F38C96BA582C52") /*  984 */, BigInt("0xCAD1BDBD7FD85DB2") /*  985 */,
                BigInt("0xBBB442C16082AE83") /*  986 */, BigInt("0xB95FE86BA5DA9AB0") /*  987 */,
                BigInt("0xB22E04673771A93F") /*  988 */, BigInt("0x845358C9493152D8") /*  989 */,
                BigInt("0xBE2A488697B4541E") /*  990 */, BigInt("0x95A2DC2DD38E6966") /*  991 */,
                BigInt("0xC02C11AC923C852B") /*  992 */, BigInt("0x2388B1990DF2A87B") /*  993 */,
                BigInt("0x7C8008FA1B4F37BE") /*  994 */, BigInt("0x1F70D0C84D54E503") /*  995 */,
                BigInt("0x5490ADEC7ECE57D4") /*  996 */, BigInt("0x002B3C27D9063A3A") /*  997 */,
                BigInt("0x7EAEA3848030A2BF") /*  998 */, BigInt("0xC602326DED2003C0") /*  999 */,
                BigInt("0x83A7287D69A94086") /* 1000 */, BigInt("0xC57A5FCB30F57A8A") /* 1001 */,
                BigInt("0xB56844E479EBE779") /* 1002 */, BigInt("0xA373B40F05DCBCE9") /* 1003 */,
                BigInt("0xD71A786E88570EE2") /* 1004 */, BigInt("0x879CBACDBDE8F6A0") /* 1005 */,
                BigInt("0x976AD1BCC164A32F") /* 1006 */, BigInt("0xAB21E25E9666D78B") /* 1007 */,
                BigInt("0x901063AAE5E5C33C") /* 1008 */, BigInt("0x9818B34448698D90") /* 1009 */,
                BigInt("0xE36487AE3E1E8ABB") /* 1010 */, BigInt("0xAFBDF931893BDCB4") /* 1011 */,
                BigInt("0x6345A0DC5FBBD519") /* 1012 */, BigInt("0x8628FE269B9465CA") /* 1013 */,
                BigInt("0x1E5D01603F9C51EC") /* 1014 */, BigInt("0x4DE44006A15049B7") /* 1015 */,
                BigInt("0xBF6C70E5F776CBB1") /* 1016 */, BigInt("0x411218F2EF552BED") /* 1017 */,
                BigInt("0xCB0C0708705A36A3") /* 1018 */, BigInt("0xE74D14754F986044") /* 1019 */,
                BigInt("0xCD56D9430EA8280E") /* 1020 */, BigInt("0xC12591D7535F5065") /* 1021 */,
                BigInt("0xC83223F1720AEF96") /* 1022 */, BigInt("0xC3A0396F7363A51F") /* 1023 */,
            ];
            inited = true;
        }
        this._digestBitLen = digestBitLen;
        this._extraPasses = extraPasses;
        this._bigEndian = bigEndian;
        this._tiger2 = tiger2;
    }
    _keySchedule() {
        this._x0 = uint(this._x0 - (this._x7 ^ BigInt("0xa5a5a5a5a5a5a5a5")));
        this._x1 ^= this._x0;
        this._x2 = (this._x2 + this._x1) & U64;
        this._x3 = uint(this._x3 - (this._x2 ^ ((~this._x1 << BigInt(19)) & U64)));
        this._x4 ^= this._x3;
        this._x5 = (this._x5 + this._x4) & U64;
        this._x6 = uint(this._x6 - (this._x5 ^ (uint(~this._x4) >> BigInt(23))));
        this._x7 ^= this._x6;
        this._x0 = (this._x0 + this._x7) & U64;
        this._x1 = uint(this._x1 - (this._x0 ^ (~this._x7 << BigInt(19))));
        this._x2 ^= this._x1;
        this._x3 = (this._x3 + this._x2) & U64;
        this._x4 = uint(this._x4 - (this._x3 ^ (uint(~this._x2) >> BigInt(23))));
        this._x5 ^= this._x4;
        this._x6 = (this._x6 + this._x5) & U64;
        this._x7 = uint(this._x7 - (this._x6 ^ BigInt("0x0123456789abcdef")));
    }
    _save() {
        this._aa = this._a.value;
        this._bb = this._b.value;
        this._cc = this._c.value;
    }
    _feedforward() {
        this._a.value ^= this._aa;
        this._b.value = uint(this._b.value - this._bb);
        this._c.value = (this._c.value + this._cc) & U64;
    }
    _compress() {
        this._save();
        this._pass(this._a, this._b, this._c, BigInt(5));
        this._keySchedule();
        this._pass(this._c, this._a, this._b, BigInt(7));
        this._keySchedule();
        this._pass(this._b, this._c, this._a, BigInt(9));
        for (let pass = 0; pass < this._extraPasses; ++pass) {
            this._keySchedule();
            this._pass(this._a, this._b, this._c, BigInt(9));
            const tmpa = this._a;
            this._a = this._c;
            this._c = this._b;
            this._b = tmpa;
        }
        this._feedforward();
    }
    _round(a, b, c, x, mul) {
        c.value ^= x;
        const d = c.value;
        const d_0 = d & BigInt(0xff);
        const d_1 = (d >> BigInt(8)) & BigInt(0xff);
        const d_2 = (d >> BigInt(16)) & BigInt(0xff);
        const d_3 = (d >> BigInt(24)) & BigInt(0xff);
        const d_4 = (d >> BigInt(32)) & BigInt(0xff);
        const d_5 = (d >> BigInt(40)) & BigInt(0xff);
        const d_6 = (d >> BigInt(48)) & BigInt(0xff);
        const d_7 = (d >> BigInt(56)) & BigInt(0xff);
        a.value = uint(a.value - BigInt(t1[Number(d_0)] ^ t2[Number(d_2)] ^ t3[Number(d_4)] ^ t4[Number(d_6)]));
        b.value = (b.value + (t4[Number(d_1)] ^ t3[Number(d_3)] ^ t2[Number(d_5)] ^ t1[Number(d_7)])) & U64;
        b.value = (b.value * mul) & U64;
    }
    _pass(a, b, c, mul) {
        this._round(a, b, c, this._x0, mul);
        this._round(b, c, a, this._x1, mul);
        this._round(c, a, b, this._x2, mul);
        this._round(a, b, c, this._x3, mul);
        this._round(b, c, a, this._x4, mul);
        this._round(c, a, b, this._x5, mul);
        this._round(a, b, c, this._x6, mul);
        this._round(b, c, a, this._x7, mul);
    }
    _split(message, block) {
        this._x0 = message[block];
        this._x1 = message[block + 1];
        this._x2 = message[block + 2];
        this._x3 = message[block + 3];
        this._x4 = message[block + 4];
        this._x5 = message[block + 5];
        this._x6 = message[block + 6];
        this._x7 = message[block + 7];
    }
    hash(input) {
        this._a = { value: BigInt("0x0123456789abcdef") };
        this._b = { value: BigInt("0xfedcba9876543210") };
        this._c = { value: BigInt("0xf096a5b4c3b2e187") };
        const words = _getMessage(input, this._tiger2);
        for (let block = 0; block < words.length; block += 8) {
            this._split(words, block);
            this._compress();
        }
        const buff = new Uint8Array(24);
        writeUint64(buff, this._a.value, !this._bigEndian, 0);
        writeUint64(buff, this._b.value, !this._bigEndian, 8);
        writeUint64(buff, this._c.value, !this._bigEndian, 16);
        const chars = this._digestBitLen / 8;
        return buff.subarray(0, chars);
    }
}
exports.Tiger = Tiger;
Tiger.L128 = 128;
Tiger.L160 = 160;
Tiger.L192 = 192;
function strToUint8Array(str) {
    // Check if the browser supports TextDecoder API
    try {
        const encoder = new TextEncoder();
        // Encode the string and return as a Uint8Array
        return encoder.encode(str);
    }
    catch (e) { }
    // Fallback for older systems without TextDecoder support
    let result = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        const codePoint = str.charCodeAt(i);
        if (codePoint <= 255) {
            result[i] = codePoint;
        }
        else {
            result.set([codePoint >> 8, codePoint & 0xFF], i * 2);
        }
    }
    return result;
}
function formatMessage(message) {
    if (message === undefined) {
        return new Uint8Array(0);
    }
    if (typeof message === 'string') {
        return strToUint8Array(message);
    }
    if (message instanceof Uint8Array || Buffer.isBuffer(message)) {
        return new Uint8Array(message);
    }
    throw new Error('input is invalid type');
}
function bytesToHex(bytes) {
    for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
    }
    return hex.join("");
}
;
/**
 * Creates a vary byte TIGER hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {128 | 160 | 192} bitLen - length of the returned hash (default 192)
 * @param {number} extraPasses - Extra cycles on the hash
 * @param {boolean} bigEndian - Is the bit order should to written in big endian (default false)
 * @returns `string | Uint8Array | Buffer`
 */
function _TIGER(message, format = arrayType(), bitLen = 192, extraPasses = 0, bigEndian = false) {
    message = formatMessage(message);
    const hash = new Tiger(bitLen, extraPasses, false);
    var digestbytes = hash.hash(message);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports._TIGER = _TIGER;
/**
 * Creates a vary byte TIGER hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {128 | 160 | 192} bitLen - length of the returned hash (default 192)
 * @param {number} extraPasses - Extra cycles on the hash
 * @param {boolean} bigEndian - Is the bit order should to written in big endian (default false)
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER_HMAC(message, key, format = arrayType(), bitLen = 192, extraPasses = 0, bigEndian = false) {
    const key_length = 64;
    const hash_len = bitLen / 8;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = _TIGER(key, "array", bitLen, extraPasses, bigEndian);
    }
    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }
    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }
    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);
    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(_TIGER(msg, "array", bitLen, extraPasses, bigEndian), key_length);
    var digestbytes = _TIGER(result, "array", bitLen, extraPasses, bigEndian);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.TIGER_HMAC = TIGER_HMAC;
/**
 * Creates a 16 byte TIGER128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER128(message, format = arrayType()) {
    message = formatMessage(message);
    const hash = new Tiger(128, 0, false, false);
    var digestbytes = hash.hash(message);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.TIGER128 = TIGER128;
/**
 * Creates a 16 byte keyed TIGER128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER128_HMAC(message, key, format = arrayType()) {
    return TIGER_HMAC(message, key, format, 128);
}
exports.TIGER128_HMAC = TIGER128_HMAC;
/**
 * Creates a 20 byte TIGER160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER160(message, format = arrayType()) {
    message = formatMessage(message);
    const hash = new Tiger(160, 0, false, false);
    var digestbytes = hash.hash(message);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.TIGER160 = TIGER160;
/**
 * Creates a 20 byte keyed TIGER160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER160_HMAC(message, key, format = arrayType()) {
    return TIGER_HMAC(message, key, format, 160);
}
exports.TIGER160_HMAC = TIGER160_HMAC;
/**
 * Creates a 24 byte TIGER192 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER192(message, format = arrayType()) {
    message = formatMessage(message);
    const hash = new Tiger(192, 0, false);
    var digestbytes = hash.hash(message);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.TIGER192 = TIGER192;
/**
 * Creates a 24 byte keyed TIGER192 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER192_HMAC(message, key, format = arrayType()) {
    return TIGER_HMAC(message, key, format, 192);
}
exports.TIGER192_HMAC = TIGER192_HMAC;
/**
 * Creates a vary byte TIGER2 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {128 | 160 | 192} bitLen - length of the returned hash (default 192)
 * @param {number} extraPasses - Extra cycles on the hash
 * @param {boolean} bigEndian - Is the bit order should to written in big endian (default false)
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER2(message, format = arrayType(), bitLen = 192, extraPasses = 0, bigEndian = false) {
    message = formatMessage(message);
    const hash = new Tiger(bitLen, extraPasses, bigEndian, true);
    var digestbytes = hash.hash(message);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.TIGER2 = TIGER2;
/**
 * Creates a vary byte keyed TIGER2 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @param {128 | 160 | 192} bitLen - length of the returned hash (default 192)
 * @param {number} extraPasses - Extra cycles on the hash
 * @param {boolean} bigEndian - Is the bit order should to written in big endian (default false)
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER2_HMAC(message, key, format = arrayType(), bitLen = 192, extraPasses = 0, bigEndian = false) {
    // TIGER192
    const key_length = 64;
    const hash_len = bitLen / 8;
    key = formatMessage(key);
    message = formatMessage(message);
    if (key.length > key_length) {
        key = TIGER2(key, "array", bitLen, extraPasses, bigEndian);
    }
    if (key.length < key_length) {
        const tmp = new Uint8Array(key_length);
        tmp.set(key, 0);
        key = tmp;
    }
    // Generate inner and outer keys
    var innerKey = new Uint8Array(key_length);
    var outerKey = new Uint8Array(key_length);
    for (var i = 0; i < key_length; i++) {
        innerKey[i] = 0x36 ^ key[i];
        outerKey[i] = 0x5c ^ key[i];
    }
    // Append the innerKey
    var msg = new Uint8Array(message.length + key_length);
    msg.set(innerKey, 0);
    msg.set(message, key_length);
    // Hash the previous message and append the outerKey
    var result = new Uint8Array(key_length + hash_len);
    result.set(outerKey, 0);
    result.set(TIGER2(msg, "array", bitLen, extraPasses, bigEndian), key_length);
    var digestbytes = TIGER2(result, "array", bitLen, extraPasses, bigEndian);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.TIGER2_HMAC = TIGER2_HMAC;
/**
 * Creates a 16 byte TIGER2-128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER2_128(message, format = arrayType()) {
    message = formatMessage(message);
    const hash = new Tiger(128, 0, false, true);
    var digestbytes = hash.hash(message);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.TIGER2_128 = TIGER2_128;
/**
 * Creates a 16 byte keyed TIGER2-128 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER2_128_HMAC(message, key, format = arrayType()) {
    return TIGER2_HMAC(message, key, format, 128);
}
exports.TIGER2_128_HMAC = TIGER2_128_HMAC;
/**
 * Creates a 20 byte TIGER2-160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER2_160(message, format = arrayType()) {
    message = formatMessage(message);
    const hash = new Tiger(160, 0, false, true);
    var digestbytes = hash.hash(message);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.TIGER2_160 = TIGER2_160;
/**
 * Creates a 20 byte keyed TIGER2-160 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER2_160_HMAC(message, key, format = arrayType()) {
    return TIGER2_HMAC(message, key, format, 160);
}
exports.TIGER2_160_HMAC = TIGER2_160_HMAC;
/**
 * Creates a 24 byte TIGER2-192 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER2_192(message, format = arrayType()) {
    message = formatMessage(message);
    const hash = new Tiger(192, 0, false, true);
    var digestbytes = hash.hash(message);
    if (format == "hex") {
        return bytesToHex(digestbytes);
    }
    else if (format == "buffer") {
        return Buffer.from(digestbytes);
    }
    return digestbytes;
}
exports.TIGER2_192 = TIGER2_192;
/**
 * Creates a 24 byte keyed TIGER2-192 hash of the message as either a hex string, Uint8Array or Buffer. Accepts strings, Uint8Array or Buffer.
 *
 * @param {InputData} message - Message to hash
 * @param {InputData} key - hash key
 * @param {OutputFormat} format - as a hex string, Uint8Array, Buffer
 * @returns `string | Uint8Array | Buffer`
 */
function TIGER2_192_HMAC(message, key, format = arrayType()) {
    return TIGER2_HMAC(message, key, format, 192);
}
exports.TIGER2_192_HMAC = TIGER2_192_HMAC;
/**
 * Static class of all TIGER functions and classes
 */
class TIGER {
    /**
     * List of all functions in class
     */
    static get FUNCTION_LIST() {
        return [
            "TIGER",
            "TIGER128",
            "TIGER128_HMAC",
            "TIGER160",
            "TIGER160_HMAC",
            "TIGER192",
            "TIGER192_HMAC",
            "TIGER_HMAC",
            "TIGER2",
            "TIGER2_128",
            "TIGER2_128_HMAC",
            "TIGER2_160",
            "TIGER2_160_HMAC",
            "TIGER2_192",
            "TIGER2_192_HMAC",
            "TIGER2_HMAC"
        ];
    }
    ;
}
exports.TIGER = TIGER;
TIGER.Tiger = Tiger;
TIGER.TIGER = _TIGER;
TIGER.TIGER128 = TIGER128;
TIGER.TIGER128_HMAC = TIGER128_HMAC;
TIGER.TIGER160 = TIGER160;
TIGER.TIGER160_HMAC = TIGER160_HMAC;
TIGER.TIGER192 = TIGER192;
TIGER.TIGER192_HMAC = TIGER192_HMAC;
TIGER.TIGER_HMAC = TIGER_HMAC;
TIGER.TIGER2 = TIGER2;
TIGER.TIGER2_128 = TIGER2_128;
TIGER.TIGER2_128_HMAC = TIGER2_128_HMAC;
TIGER.TIGER2_160 = TIGER2_160;
TIGER.TIGER2_160_HMAC = TIGER2_160_HMAC;
TIGER.TIGER2_192 = TIGER2_192;
TIGER.TIGER2_192_HMAC = TIGER2_192_HMAC;
TIGER.TIGER2_HMAC = TIGER2_HMAC;
//# sourceMappingURL=TIGER.js.map