#include <algorithm>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>

using namespace std;
static constexpr int TOTAL_PUZZLES   = 256;
static constexpr int INDEX_WIDTH     = 3;
static constexpr int PRIV_HEX_WIDTH  = 64;
static constexpr int ADDR_WIDTH      = 34;
static constexpr int WIF_WIDTH       = 44;
static constexpr int PCT_WIDTH       = 7;

namespace ansi {
    constexpr const char* GREEN = "\033[32m";
    constexpr const char* RED   = "\033[31m";
    constexpr const char* RESET = "\033[0m";
}

struct Puzzle {
    int    number;
    string privateKey;    // 64-char hex or empty
    string walletAddress; // Base58Check or empty
};


extern const Puzzle puzzles[TOTAL_PUZZLES] = {
    {1, "0000000000000000000000000000000000000000000000000000000000000001", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"},
    {2, "0000000000000000000000000000000000000000000000000000000000000003", "1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb"},
    {3, "0000000000000000000000000000000000000000000000000000000000000007", "19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA"},
    {4, "0000000000000000000000000000000000000000000000000000000000000008", "1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e"},
    {5, "0000000000000000000000000000000000000000000000000000000000000015", "1E6NuFjCi27W5zoXg8TRdcSRq84zJeBW3k"},
    {6, "0000000000000000000000000000000000000000000000000000000000000031", "1PitScNLyp2HCygzadCh7FveTnfmpPbfp8"},
    {7, "000000000000000000000000000000000000000000000000000000000000004C", "1McVt1vMtCC7yn5b9wgX1833yCcLXzueeC"},
    {8, "00000000000000000000000000000000000000000000000000000000000000E0", "1M92tSqNmQLYw33fuBvjmeadirh1ysMBxK"},
    {9, "00000000000000000000000000000000000000000000000000000000000001D3", "1CQFwcjw1dwhtkVWBttNLDtqL7ivBonGPV"},
    {10, "0000000000000000000000000000000000000000000000000000000000000202", "1LeBZP5QCwwgXRtmVUvTVrraqPUokyLHqe"},
    {11, "0000000000000000000000000000000000000000000000000000000000000483", "1PgQVLmst3Z314JrQn5TNiys8Hc38TcXJu"},
    {12, "0000000000000000000000000000000000000000000000000000000000000A7B", "1DBaumZxUkM4qMQRt2LVWyFJq5kDtSZQot"},
    {13, "0000000000000000000000000000000000000000000000000000000000001460", "1Pie8JkxBT6MGPz9Nvi3fsPkr2D8q3GBc1"},
    {14, "0000000000000000000000000000000000000000000000000000000000002930", "1ErZWg5cFCe4Vw5BzgfzB74VNLaXEiEkhk"},
    {15, "00000000000000000000000000000000000000000000000000000000000068F3", "1QCbW9HWnwQWiQqVo5exhAnmfqKRrCRsvW"},
    {16, "000000000000000000000000000000000000000000000000000000000000C936", "1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY"},
    {17, "000000000000000000000000000000000000000000000000000000000001764F", "1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm"},
    {18, "000000000000000000000000000000000000000000000000000000000003080D", "1GnNTmTVLZiqQfLbAdp9DVdicEnB5GoERE"},
    {19, "000000000000000000000000000000000000000000000000000000000005749F", "1NWmZRpHH4XSPwsW6dsS3nrNWfL1yrJj4w"},
    {20, "00000000000000000000000000000000000000000000000000000000000D2C55", "1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum"},
    {21, "00000000000000000000000000000000000000000000000000000000001BA534", "14oFNXucftsHiUMY8uctg6N487riuyXs4h"},
    {22, "00000000000000000000000000000000000000000000000000000000002DE40F", "1CfZWK1QTQE3eS9qn61dQjV89KDjZzfNcv"},
    {23, "0000000000000000000000000000000000000000000000000000000000556E52", "1L2GM8eE7mJWLdo3HZS6su1832NX2txaac"},
    {24, "0000000000000000000000000000000000000000000000000000000000DC2A04", "1rSnXMr63jdCuegJFuidJqWxUPV7AtUf7"},
    {25, "0000000000000000000000000000000000000000000000000000000001FA5EE5", "15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP"},
    {26, "000000000000000000000000000000000000000000000000000000000340326E", "1JVnST957hGztonaWK6FougdtjxzHzRMMg"},
    {27, "0000000000000000000000000000000000000000000000000000000006AC3875", "128z5d7nN7PkCuX5qoA4Ys6pmxUYnEy86k"},
    {28, "000000000000000000000000000000000000000000000000000000000D916CE8", "12jbtzBb54r97TCwW3G1gCFoumpckRAPdY"},
    {29, "0000000000000000000000000000000000000000000000000000000017E2551E", "19EEC52krRUK1RkUAEZmQdjTyHT7Gp1TYT"},
    {30, "000000000000000000000000000000000000000000000000000000003D94CD64", "1LHtnpd8nU5VHEMkG2TMYYNUjjLc992bps"},
    {31, "000000000000000000000000000000000000000000000000000000007D4FE747", "1LhE6sCTuGae42Axu1L1ZB7L96yi9irEBE"},
    {32, "00000000000000000000000000000000000000000000000000000000B862A62E", "1FRoHA9xewq7DjrZ1psWJVeTer8gHRqEvR"},
    {33, "00000000000000000000000000000000000000000000000000000001A96CA8D8", "187swFMjz1G54ycVU56B7jZFHFTNVQFDiu"},
    {34, "000000000000000000000000000000000000000000000000000000034A65911D", "1PWABE7oUahG2AFFQhhvViQovnCr4rEv7Q"},
    {35, "00000000000000000000000000000000000000000000000000000004AED21170", "1PWCx5fovoEaoBowAvF5k91m2Xat9bMgwb"},
    {36, "00000000000000000000000000000000000000000000000000000009DE820A7C", "1Be2UF9NLfyLFbtm3TCbmuocc9N1Kduci1"},
    {37, "0000000000000000000000000000000000000000000000000000001757756A93", "14iXhn8bGajVWegZHJ18vJLHhntcpL4dex"},
    {38, "00000000000000000000000000000000000000000000000000000022382FACD0", "1HBtApAFA9B2YZw3G2YKSMCtb3dVnjuNe2"},
    {39, "0000000000000000000000000000000000000000000000000000004B5F8303E9", "122AJhKLEfkFBaGAd84pLp1kfE7xK3GdT8"},
    {40, "000000000000000000000000000000000000000000000000000000E9AE4933D6", "1EeAxcprB2PpCnr34VfZdFrkUWuxyiNEFv"},
    {41, "00000000000000000000000000000000000000000000000000000153869ACC5B", "1L5sU9qvJeuwQUdt4y1eiLmquFxKjtHr3E"},
    {42, "000000000000000000000000000000000000000000000000000002A221C58D8F", "1E32GPWgDyeyQac4aJxm9HVoLrrEYPnM4N"},
    {43, "000000000000000000000000000000000000000000000000000006BD3B27C591", "1PiFuqGpG8yGM5v6rNHWS3TjsG6awgEGA1"},
    {44, "00000000000000000000000000000000000000000000000000000E02B35A358F", "1CkR2uS7LmFwc3T2jV8C1BhWb5mQaoxedF"},
    {45, "0000000000000000000000000000000000000000000000000000122FCA143C05", "1NtiLNGegHWE3Mp9g2JPkgx6wUg4TW7bbk"},
    {46, "00000000000000000000000000000000000000000000000000002EC18388D544", "1F3JRMWudBaj48EhwcHDdpeuy2jwACNxjP"},
    {47, "00000000000000000000000000000000000000000000000000006CD610B53CBA", "1Pd8VvT49sHKsmqrQiP61RsVwmXCZ6ay7Z"},
    {48, "0000000000000000000000000000000000000000000000000000ADE6D7CE3B9B", "1DFYhaB2J9q1LLZJWKTnscPWos9VBqDHzv"},
    {49, "000000000000000000000000000000000000000000000000000174176B015F4D", "12CiUhYVTTH33w3SPUBqcpMoqnApAV4WCF"},
    {50, "00000000000000000000000000000000000000000000000000022BD43C2E9354", "1MEzite4ReNuWaL5Ds17ePKt2dCxWEofwk"},
    {51, "00000000000000000000000000000000000000000000000000075070A1A009D4", "1NpnQyZ7x24ud82b7WiRNvPm6N8bqGQnaS"},
    {52, "000000000000000000000000000000000000000000000000000EFAE164CB9E3C", "15z9c9sVpu6fwNiK7dMAFgMYSK4GqsGZim"},
    {53, "00000000000000000000000000000000000000000000000000180788E47E326C", "15K1YKJMiJ4fpesTVUcByoz334rHmknxmT"},
    {54, "00000000000000000000000000000000000000000000000000236FB6D5AD1F43", "1KYUv7nSvXx4642TKeuC2SNdTk326uUpFy"},
    {55, "000000000000000000000000000000000000000000000000006ABE1F9B67E114", "1LzhS3k3e9Ub8i2W1V8xQFdB8n2MYCHPCa"},
    {56, "000000000000000000000000000000000000000000000000009D18B63AC4FFDF", "17aPYR1m6pVAacXg1PTDDU7XafvK1dxvhi"},
    {57, "00000000000000000000000000000000000000000000000001EB25C90795D61C", "15c9mPGLku1HuW9LRtBf4jcHVpBUt8txKz"},
    {58, "00000000000000000000000000000000000000000000000002C675B852189A21", "1Dn8NF8qDyyfHMktmuoQLGyjWmZXgvosXf"},
    {59, "00000000000000000000000000000000000000000000000007496CBB87CAB44F", "1HAX2n9Uruu9YDt4cqRgYcvtGvZj1rbUyt"},
    {60, "0000000000000000000000000000000000000000000000000FC07A1825367BBE", "1Kn5h2qpgw9mWE5jKpk8PP4qvvJ1QVy8su"},
    {61, "00000000000000000000000000000000000000000000000013C96A3742F64906", "1AVJKwzs9AskraJLGHAZPiaZcrpDr1U6AB"},
    {62, "000000000000000000000000000000000000000000000000363D541EB611ABEE", "1Me6EfpwZK5kQziBwBfvLiHjaPGxCKLoJi"},
    {63, "0000000000000000000000000000000000000000000000007CCE5EFDACCF6808", "1NpYjtLira16LfGbGwZJ5JbDPh3ai9bjf4"},
    {64, "000000000000000000000000000000000000000000000000F7051F27B09112D4", "16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN"},
    {65, "000000000000000000000000000000000000000000000001A838B13505B26867", "18ZMbwUFLMHoZBbfpCjUJQTCMCbktshgpe"},
    {66, "000000000000000000000000000000000000000000000002832ED74F2B5E35EE", "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"},
    {67, "00000000000000000000000000000000000000000000000730FC235C1942C1AE", "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9"},
    {68, "00000000000000000000000000000000000000000000000BEBB3940CD0FC1491", "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ"},
    {69, "0000000000000000000000000000000000000000000000101D83275FB2BC7E0C", "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG"},
    {70, "0000000000000000000000000000000000000000000000349B84B6431A6C4EF1", "19YZECXj3SxEZMoUeJ1yiPsw8xANe7M7QR"},
    {71, "", "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"},
    {72, "", "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR"},
    {73, "", "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4"},
    {74, "", "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv"},
    {75, "0000000000000000000000000000000000000000000004C5CE114686A1336E07", "1J36UjUByGroXcCvmj13U6uwaVv9caEeAt"},
    {76, "", "1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF"},
    {77, "", "1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE"},
    {78, "", "15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb"},
    {79, "", "1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8"},
    {80, "00000000000000000000000000000000000000000000EA1A5C66DCC11B5AD180", "1BCf6rHUW6m3iH2ptsvnjgLruAiPQQepLe"},
    {81, "", "15QSCM78WHSPNQFYDGJQK5REXZXTQOPNHZ"},
    {82, "", "13ZYRYHHJXP6UI1VV7PQA5WDHNWM45ARAC"},
    {83, "", "14MDEB4EFCT3MVG5SPFG4JGLUHJSNT1DK2"},
    {84, "", "1CMQ3SVFCVECPLMUUH8PUCNIQSK1OICG2D"},
    {85, "00000000000000000000000000000000000000000011720C4F018D51B8CEBBA8", "1Kh22PvXERd2xpTQk3ur6pPEqFeckCJfAr"},
    {86, "", "1K3X5L6G57Y494FDQBFROJD28UJV4S5JCK"},
    {87, "", "1PXH3K1SHDJB7GSEOTX7UPDZ6SH4QGPRVQ"},
    {88, "", "16ABNZJZZIPWHMKYKBSFSWGWKDMXHJEPSF"},
    {89, "", "19QCIEHBGVNY4HRHFKXMCBBCRJSBZ6TAVT"},
    {90, "000000000000000000000000000000000000000002CE00BB2136A445C71E85BF", "1L12FHH2FHjvTviyanuiFVfmzCy46RRATU"},
    {91, "", "1EZVHTMBN4FS4MINK3PPENKKHSMXYJ4S74"},
    {92, "", "1AE8NZZGKE7YHZ7BWTACAAXIFMBPO82NB5"},
    {93, "", "17Q7TUG2JWFFU9RXVJ3UZQRTIOH3MX2JAD"},
    {94, "", "1K6XGMUBS6ZTXBNHW1PIPPQWK6WJBWTNPL"},
    {95, "0000000000000000000000000000000000000000527A792B183C7F64A0E8B1F4", "19eVSDuizydXxhohGh8Ki9WY9KsHdSwoQC"},
    {96, "", "15ANYZZCP5BFHCCNVFZXQYIBPZGPLWAD8B"},
    {97, "", "18YWPWJ39NGJQBRQJSZZVQ2IZR12MDPDR8"},
    {98, "", "1CABVPRWUXBQYYSWU32W7MJ4HR4MANOJSX"},
    {99, "", "1JWNE6P6UN7ZJBN7TTCBNDORCJFTUDWONL"},
    {100, "000000000000000000000000000000000000000AF55FC59C335C8EC67ED24826", "1KCgMv8fo2TPBpddVi9jqmMmcne9uSNJ5F"},
    {101, "", "1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n"},
    {102, "", "1PXv28YxmYMaB8zxrKeZBW8dt2HK7RkRPX"},
    {103, "", "1AcAmB6jmtU6AiEcXkmiNE9TNVPsj9DULf"},
    {104, "", "1EQJvpsmhazYCcKX5Au6AZmZKRnzarMVZu"},
    {105, "000000000000000000000000000000000000016F14FC2054CD87EE6396B33DF3", "1CMjscKB3QW7SDyQ4c3C3DEUHiHRhiZVib"},
    {106, "", "18KsfuHuzQaBTNLASyj15hy4LuqPUo1FNB"},
    {107, "", "15EJFC5ZTs9nhsdvSUeBXjLAuYq3SWaxTc"},
    {108, "", "1HB1iKUqeffnVsvQsbpC6dNi1XKbyNuqao"},
    {109, "", "1GvgAXVCbA8FBjXfWiAms4ytFeJcKsoyhL"},
    {110, "00000000000000000000000000000000000035C0D7234DF7DEB0F20CF7062444", "12JzYkkN76xkwvcPT6AWKzTGX6w2LAgsJg"},
    {111, "", "1824ZJQ7nKJ9QFTRBqn7z7dHV5EGpzUpH3"},
    {112, "", "18A7NA9FTsnJxWgkoFfPAFbQzuQxpRtCos"},
    {113, "", "1NeGn21dUDDeqFQ63xb2SpgUuXuBLA4WT4"},
    {114, "", "174SNxfqpdMGYy5YQcfLbSTK3MRNZEePoy"},
    {115, "0000000000000000000000000000000000060F4D11574F5DEEE49961D9609AC6", "1NLbHuJebVwUZ1XqDjsAyfTRUPwDQbemfv"},
    {116, "", "1MnJ6hdhvK37VLmqcdEwqC3iFxyWH2PHUV"},
    {117, "", "1KNRfGWw7Q9Rmwsc6NT5zsdvEb9M2Wkj5Z"},
    {118, "", "1PJZPzvGX19a7twf5HyD2VvNiPdHLzm9F6"},
    {119, "", "1GuBBhf61rnvRe4K8zu8vdQB3kHzwFqSy7"},
    {120, "0000000000000000000000000000000000B10F22572C497A836EA187F2E1FC23", "17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT"},
    {121, "", "1GDSuiThEV64c166LUFC9uDcVdGjqkxKyh"},
    {122, "", "1Me3ASYt5JCTAK2XaC32RMeH34PdprrfDx"},
    {123, "", "1CdufMQL892A69KXgv6UNBD17ywWqYpKut"},
    {124, "", "1BkkGsX9ZM6iwL3zbqs7HWBV7SvosR6m8N"},
    {125, "000000000000000000000000000000001C533B6BB7F0804E09960225E44877AC", "1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5"},
    {126, "", "1AWCLZAjKbV1P7AHvaPNCKiB7ZWVDMxFiz"},
    {127, "", "1G6EFyBRU86sThN3SSt3GrHu1sA7w7nzi4"},
    {128, "", "1MZ2L1gFrCtkkn6DnTT2e4PFUTHw9gNwaj"},
    {129, "", "1Hz3uv3nNZzBVMXLGadCucgjiCs5W9vaGz"},
    {130, "000000000000000000000000000000033E7665705359F04F28B88CF897C603C9", "1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua"},
    {131, "", "16zRPnT8znwq42q7XeMkZUhb1bKqgRogyy"},
    {132, "", "1KrU4dHE5WrW8rhWDsTRjR21r8t3dsrS3R"},
    {133, "", "17uDfp5r4n441xkgLFmhNoSW1KWp6xVLD"},
    {134, "", "13A3JrvXmvg5w9XGvyyR4JEJqiLz8ZySY3"},
    {135, "", "16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v"},
    {136, "", "1UDHPdovvR985NrWSkdWQDEQ1xuRiTALq"},
    {137, "", "15nf31J46iLuK1ZkTnqHo7WgN5cARFK3RA"},
    {138, "", "1Ab4vzG6wEQBDNQM1B2bvUz4fqXXdFk2WT"},
    {139, "", "1Fz63c775VV9fNyj25d9Xfw3YHE6sKCxbt"},
    {140, "", "1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo"},
    {141, "", "1CD91Vm97mLQvXhrnoMChhJx4TP9MaQkJo"},
    {142, "", "15MnK2jXPqTMURX4xC3h4mAZxyCcaWWEDD"},
    {143, "", "13N66gCzWWHEZBxhVxG18P8wyjEWF9Yoi1"},
    {144, "", "1NevxKDYuDcCh1ZMMi6ftmWwGrZKC6j7Ux"},
    {145, "", "19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg"},
    {146, "", "1M7ipcdYHey2Y5RZM34MBbpugghmjaV89P"},
    {147, "", "18aNhurEAJsw6BAgtANpexk5ob1aGTwSeL"},
    {148, "", "1FwZXt6EpRT7Fkndzv6K4b4DFoT4trbMrV"},
    {149, "", "1CXvTzR6qv8wJ7eprzUKeWxyGcHwDYP1i2"},
    {150, "", "1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy"},
    {151, "", "13Q84TNNvgcL3HJiqQPvyBb9m4hxjS3jkV"},
    {152, "", "1LuUHyrQr8PKSvbcY1v1PiuGuqFjWpDumN"},
    {153, "", "18192XpzzdDi2K11QVHR7td2HcPS6Qs5vg"},
    {154, "", "1NgVmsCCJaKLzGyKLFJfVequnFW9ZvnMLN"},
    {155, "", "1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ"},
    {156, "", "1FTpAbQa4h8trvhQXjXnmNhqdiGBd1oraE"},
    {157, "", "14JHoRAdmJg3XR4RjMDh6Wed6ft6hzbQe9"},
    {158, "", "19z6waranEf8CcP8FqNgdwUe1QRxvUNKBG"},
    {159, "", "14u4nA5sugaswb6SZgn5av2vuChdMnD9E5"},
    {160, "", "1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv"},
    {161, "", "1JkqBQcC4tHcb1JfdCH6nrWYwTPGznHANh"},
    {162, "", "17DTUTXUcUYEgrr5GhivxYei4Lrs1xoMnS2"},
    {163, "", "1H6e7SLxv6ZUbuAaZpeUdVNfh3cKBWJRmx"},
    {164, "", "1LjQKurNtEDgMdqeCoWRFhHp1FPnLU77Q4"},
    {165, "", "1F7ZjibYug9bLW3YvkkwBZLrhfLtNjgYrX"},
    {166, "", "12BtvPaamiBCpXmoDrsCxAa1b6hMRnASZ4"},
    {167, "", "1AvLwGpkwTZH4qiwy1L4v6TuWXLMNrATN5"},
    {168, "", "1PojqbbzJHnn1X2mv6DCECNLUaD2nMssDp"},
    {169, "", "1G3uazv67BcKRmPFvgvX4ijBTa2898cvCm"},
    {170, "", "1EW9W5sGdxVDxAtjRbCjgkZNtPH8ZzikeP"},
    {171, "", "17zzMMnj5h8StLhnrXpw8iBP21uujNC4Ap"},
    {172, "", "15LJKhwQJ7dYMBZX1mktskZqxX1aUCibkr"},
    {173, "", "1Mkodin3C3drVaV9JNk1o3i4n4gVGe9GVx"},
    {174, "", "1C6dHU1gQtVUXZmeXQuQc3EgDJbiLbxFZJ"},
    {175, "", "1DxZJy7AkqLVAQ5rtSUKfrR3yPE5u5ygk6"},
    {176, "", "1NcytLwdqJa8DsQPa9NwkxJTQcx1rZy85A"},
    {177, "", "163vG9mKmAsrvmq42MBDPjf9axZyEgBc9R"},
    {178, "", "12ATwA5VvoPDinSymcQpCAXPLApAVLN24z"},
    {179, "", "12fXbBE7kTfqYk8dYyU9bw7XfKVwEqXnzg"},
    {180, "", "1EkYsB1C7deWxiVUULeZpr42AdYWhv4PEX"},
    {181, "", "1MPQyhXBT2FpUMCiv5YX3yacKvmc9P5x6S"},
    {182, "", "1GZyxmpgtRJNaW1zEhPAa81xZDEJSdwbbZ"},
    {183, "", "12E2HWQVHzuGKAQVvPUkHWwibAJfnmcHW1"},
    {184, "", "14J1fXY2E3fbxjp1zpfqRhk5BNQ4pb97Rs"},
    {185, "", "1HqHHuFzZhtTtyGbAWCS49qGnCBSEhBSFT"},
    {186, "", "1BJXBDt4e1uaorXPototucUGNRme57nAqt"},
    {187, "", "19ct7Egfi5j6jSefj8X4d5eXJQUmyhtXjC"},
    {188, "", "1DyWSY1dA3wyjo4eMuQCPfrm3dV96xDDSU"},
    {189, "", "1PiLrDyeXtncnsvcVAGGcNnpzQVRCG3fwS"},
    {190, "", "1HUoYzoEn2a4WxKvnYYbnR9GKrVqAfq7oY"},
    {191, "", "19vnME8b28SzJDuEFNShAG5JCR63V1zzV"},
    {192, "", "1GWTEv76C8cusq4h5gV3rLjeFhBkGBHSKg"},
    {193, "", "1NHh2fQDm7KyBs8HRFkVtHgMzkmufk6mNW"},
    {194, "", "1oW8VFRNVKhbzzq8NWNutDYDzv1CzAHAj"},
    {195, "", "16q15tpaHQFUENUmRPLgiidCMWLcDpVEgs"},
    {196, "", "1AH4d8Bss6eFyugZaN2qPXMBH69T946dSK"},
    {197, "", "12gDPuHvZBh6FSjyhHhyDDmM38Y2wyDGQt"},
    {198, "", "12jFRwZFUrxUTtuyVzw9FNJsJa7mjBgfca"},
    {199, "", "1BNkFNU3eJz8jDfTkTwe7XmF18BfQwfqW7"},
    {200, "", "1DEDEKJVEmXvEqwg3wbq8c1ZNobo4tNw4h"},
    {201, "", "1DA2RexqNkbVhzfkmQDHRMfKrdesgyMMdQ"},
    {202, "", "19Ho5YB6y8qRCdUMxWpXqrm8N4AKAq7ZWS"},
    {203, "", "1DVWn7PuRBmsdTBKiboBdSREHdAtSoN6BB"},
    {204, "", "14CMU6qvv55Y7xJdVw64ey5yfUP4BZAjct"},
    {205, "", "1DHL5NuXPjwDsNnXyzAgZTAMM4aYUc1zFW"},
    {206, "", "1UwsEPMF1NZTWJAuymsLVJpqetBZ3Q9sJ"},
    {207, "", "16aELF1f75o464ZhtAZUwbc4ctFQZxS8qi"},
    {208, "", "15TJ3wPvdviupvKQFm8hLeXSzeMSq7LSJ2"},
    {209, "", "1JgrGoQbvJS7UnX6j4myiCxo6Q3gyo5Ujk"},
    {210, "", "14Xm5DjBUQTJCzeGhyrhVsxkK8p35srk1S"},
    {211, "", "19yhSoza8oK3ioCSydMuAGJs4Mm3FwCTht"},
    {212, "", "1JXw9i8dEZGH29mUiuKjWXK9L27r2TerLQ"},
    {213, "", "1CNNth43uiVypxHmZLC8hWZsb7UiP7wSkY"},
    {214, "", "16ocVeZDpqcvyMvzAH1r2LR75uEzRhkyV2"},
    {215, "", "15x3tRVyn9SRaxfbFUzqETmCJiz46Vs247"},
    {216, "", "197K7MdYhnN88gcJouJRxMiSAHHfWuPrXC"},
    {217, "", "1MDsNYfC4LErgwUDqfQ5BgFJqv5bs4Frkn"},
    {218, "", "1BDTXmiyyzq9i79RGGTW7cjmYJbxKoV27e"},
    {219, "", "1EiJ59LPWDezXwfAGFTcoEKdNhvRTriBXy"},
    {220, "", "1rirV4Y2NxGwKNQNojJhz61jEctni8fvb"},
    {221, "", "1NxgWntAdMugSNFHEXYizYwk3UjxKPxcDF"},
    {222, "", "17A75vEkPPVeY9MMMXUY9M2JUHbbNyVAWC"},
    {223, "", "1NUVBXgX35Uax4fpziV7VGMJyji3mUzZbt"},
    {224, "", "1F6yxcbDzjumeN77DiABMXzPcvtAdnaoPF"},
    {225, "", "16YvGEYhAwjf2duwvH8jbFMfVCnY6XiQTq"},
    {226, "", "1HtbZg9mPjYcMDMDNyXaFjHX5e7ZPUwWAp"},
    {227, "", "15a9nXpjnQzw2o5kmvGyKzv7anZkYFHwdK"},
    {228, "", "18zsQK8ezT32qCqgLJQMkhqyKNwpCP3JU3"},
    {229, "", "1AaBhpTnfCin9nCrai2msXzCHoVmwkAe2N"},
    {230, "", "13Jtm1mm33Uke7PbmTBYGNZGU7rXUsVs3e"},
    {231, "", "18aBXRctVrWN9naDGhKrLdZViNfLJfCdbF"},
    {232, "", "1MEEjd99pkEyCdiqVSCa8Jqjaun7fsEXaG"},
    {233, "", "1NnefTEeKQQAts37cQHzVx8oPrUu8LWyUK"},
    {234, "", "1FYbLcutmRbvu4yUeLmC4TES2Q3ChhXYY"},
    {235, "", "1Pp61TfkztZ9ckpdeUVCzbyA7vMqXAVsdV"},
    {236, "", "1PytbQzRaf9eTpGax3c6ofKwtbxaLLSNy1"},
    {237, "", "194bRtNQVRq4xi26UJZYTHexvLXijpzp3e"},
    {238, "", "1DxBvzRMdvzop21DhnDJv4xJDYFGVtu7KZ"},
    {239, "", "1QLHLvM6XKwygyWqo2cCPbfbf6woZzGEKH"},
    {240, "", "1C8Hw6T5jypz92cNFr9Lkx4Xmr4DtP7zGA"},
    {241, "", "1L7ZNx5gFPvdVPfdgFBnEUgA64woQwopqr"},
    {242, "", "1EMhTbC4Kp8DYBk5zoLsTqZ2YakhiTgQYh"},
    {243, "", "19CqmBBJ3H8FjxSSeSjv2Kn1cVQFXMY6AM"},
    {244, "", "1KMHDrCGho2QuK59UNvfjuiPdDZSgRbneC"},
    {245, "", "1HzpmnHxpu4tCJ23ZS9TfWCoX8mXfpdHiq"},
    {246, "", "1LrrNP28PYg1N1z5Uo1gR8cmoPc8h4orBZ"},
    {247, "", "14D2d3WnHThUxyPhGoj2AabBTxpZcoHy3t"},
    {248, "", "18oqrdP6uBKsn57gvmWzLuKMAY4ShapiAU"},
    {249, "", "1Bun4VzuBJ7SUoQn97dinVfDyWAS336Ldg"},
    {250, "", "1Ruu3JwvGeSmhQV9GzWAnyLCz6g3evmTY"},
    {251, "", "1M3u4q5Q35qtQPmDHeubVbk7APYi3VVoBX"},
    {252, "", "1CaTxB3YwmXZkDnTK4rRvq61SRqs48xmui"},
    {253, "", "1JqRqUPHHcQu2yrr8JZzxSYDx2jbZxEqFj"},
    {254, "", "1NKkjFvXmovmjwgUujw655n3BbEvnncyza"},
    {255, "", "17PEUvQmgqPkkvRkMowoR1wRDXYzre4b9Z"},
    {256, "", "1FMcotmnqqE5M2x9DDX3VfPAPuBWArGisa"},
};

// Convert hex string to byte vector
vector<unsigned char> hex2vec(const string &hex) {
    vector<unsigned char> v;
    v.reserve(hex.size()/2);
    for (size_t i = 0; i+1 < hex.size(); i += 2) {
        v.push_back(static_cast<unsigned char>(stoul(hex.substr(i,2), nullptr, 16)));
    }
    return v;
}

// Convert byte vector to uppercase hex string
string vec2hex(const vector<unsigned char> &v) {
    ostringstream oss;
    oss << hex << uppercase << setfill('0');
    for (auto b: v) oss << setw(2) << (int)b;
    return oss.str();
}

// Base58 encoding
static const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
string base58Encode(const vector<unsigned char>& input) {
    vector<unsigned char> tmp(input.begin(), input.end());
    size_t zeros = 0;
    while (zeros < tmp.size() && tmp[zeros] == 0) ++zeros;
    vector<unsigned char> b58((tmp.size()-zeros)*138/100+1);
    for (size_t i = zeros; i < tmp.size(); ++i) {
        int carry = tmp[i];
        for (int j = b58.size()-1; j >= 0; --j) {
            carry += 256 * b58[j]; b58[j] = carry % 58; carry /= 58;
        }
    }
    size_t it = 0; while (it < b58.size() && b58[it] == 0) ++it;
    string res; res.reserve(zeros + (b58.size()-it));
    res.assign(zeros, '1');
    for (; it < b58.size(); ++it) res += BASE58_ALPHABET[b58[it]];
    return res;
}

// Generate P2PKH compressed address from private-key hex
string privHexToAddress(const string &privHex) {
    BIGNUM* bn = BN_new(); BN_hex2bn(&bn, privHex.c_str());
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_set_conv_form(ec, POINT_CONVERSION_COMPRESSED);
    EC_KEY_set_private_key(ec, bn);
    const EC_GROUP* grp = EC_KEY_get0_group(ec);
    EC_POINT* pub = EC_POINT_new(grp);
    EC_POINT_mul(grp, pub, bn, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(ec, pub);
    unsigned char buf[33], *p = buf;
    int len = i2o_ECPublicKey(ec, &p);
    unsigned char sha[SHA256_DIGEST_LENGTH]; SHA256(buf, len, sha);
    unsigned char ripemd[RIPEMD160_DIGEST_LENGTH]; RIPEMD160(sha, SHA256_DIGEST_LENGTH, ripemd);
    vector<unsigned char> payload(1 + RIPEMD160_DIGEST_LENGTH);
    payload[0] = 0x00;
    memcpy(payload.data()+1, ripemd, RIPEMD160_DIGEST_LENGTH);
    unsigned char c1[SHA256_DIGEST_LENGTH], c2[SHA256_DIGEST_LENGTH];
    SHA256(payload.data(), payload.size(), c1);
    SHA256(c1, SHA256_DIGEST_LENGTH, c2);
    payload.insert(payload.end(), c2, c2+4);
    string addr = base58Encode(payload);
    EC_POINT_free(pub); EC_KEY_free(ec); BN_free(bn);
    return addr;
}

// Convert private bytes to WIF
string privToWIF(const vector<unsigned char>& priv) {
    vector<unsigned char> d{0x80}; d.insert(d.end(), priv.begin(), priv.end()); d.push_back(0x01);
    unsigned char h1[SHA256_DIGEST_LENGTH], h2[SHA256_DIGEST_LENGTH];
    SHA256(d.data(), d.size(), h1); SHA256(h1, SHA256_DIGEST_LENGTH, h2);
    d.insert(d.end(), h2, h2+4);
    return base58Encode(d);
}

// Compute percentage of range covered
string computeRangePercent(BIGNUM* bn, int bits, BN_CTX* ctx) {
    BIGNUM* minBN = BN_new(); BN_set_bit(minBN, bits-1);
    BIGNUM* maxBN = BN_new(); BN_set_bit(maxBN, bits); BN_sub_word(maxBN,1);
    BIGNUM* rng = BN_new(); BN_sub(rng, maxBN, minBN);
    BIGNUM* off = BN_new(); BN_sub(off, bn, minBN);
    BN_mul_word(off, 10000);
    BIGNUM* pct = BN_new(); BN_div(pct, nullptr, off, rng, ctx);
    unsigned long q = BN_get_word(pct);
    unsigned whole = q/100, frac = q%100;
    ostringstream oss; oss << whole << '.' << setw(2) << setfill('0') << frac << '%';
    BN_free(minBN); BN_free(maxBN); BN_free(rng); BN_free(off); BN_free(pct);
    return oss.str();
}

// Print table header
void printHeader() {
    cout << "#" << setw(INDEX_WIDTH+1) << "Idx" << ' '
         << left << setw(PRIV_HEX_WIDTH) << "PrivKey" << ' '
         << setw(ADDR_WIDTH)   << "Address" << ' '
         << setw(WIF_WIDTH)    << "WIF" << ' '
         << right<< setw(PCT_WIDTH)   << "%Range" << ' '
         << "Status" << '\n';
    cout << string(INDEX_WIDTH+1+1+PRIV_HEX_WIDTH+1+ADDR_WIDTH+1+WIF_WIDTH+1+PCT_WIDTH+1+6, '-') << '\n';
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc > 4) {
        cerr << "Usage: " << argv[0] << " <count> <masterSeed> [hideNonMatches]\n";
        return 1;
    }
    int count = stoi(argv[1]);
    if (count < 1 || count > TOTAL_PUZZLES) {
        cerr << "count must be between 1 and " << TOTAL_PUZZLES << "\n";
        return 1;
    }
    bool hideNonMatches = true;

    if (argc == 4) {
        hideNonMatches = string(argv[3]) == "true" || string(argv[3]) == "1";
    }

    // Master seed processing
    vector<unsigned char> keyData;
    string seedHex;
    string seedArg = argv[2];
    bool isHex = (seedArg.size()==64 && all_of(seedArg.begin(), seedArg.end(), ::isxdigit));
    if (isHex) {
        keyData = hex2vec(seedArg);
        seedHex = seedArg;
    } else {
        unsigned char sh[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char*)seedArg.data(), seedArg.size(), sh);
        keyData.assign(sh, sh+SHA256_DIGEST_LENGTH);
        seedHex = vec2hex(keyData);
    }

    BN_CTX* ctx = BN_CTX_new();
    printHeader();

    for (int i = 1; i <= count; ++i) {
        // HMAC-SHA256(masterSeed, index)
        unsigned char idx[4] = {static_cast<unsigned char>((i>>24)&0xFF), static_cast<unsigned char>((i>>16)&0xFF),
                               static_cast<unsigned char>((i>>8)&0xFF), static_cast<unsigned char>(i&0xFF)};
        unsigned int len = 0;
        unsigned char dig[SHA256_DIGEST_LENGTH];
        HMAC(EVP_sha256(), keyData.data(), keyData.size(), idx, sizeof(idx), dig, &len);

        BIGNUM* bn = BN_bin2bn(dig, len, nullptr);
        BN_mask_bits(bn, i);
        BN_set_bit(bn, i-1);

        vector<unsigned char> privBytes(32);
        BN_bn2binpad(bn, privBytes.data(), privBytes.size());
        string privHex = vec2hex(privBytes);

        // Determine address and match
        const Puzzle &p = puzzles[i-1];
        bool match = false;
        string address;
        if (!p.privateKey.empty()) {
            match = (privHex == p.privateKey);
            address = p.walletAddress;
        } else {
            address = privHexToAddress(privHex);
            match = (!p.walletAddress.empty() && address==p.walletAddress);
        }

        string wif  = privToWIF(privBytes);
        string pct  = computeRangePercent(bn, i, ctx);
        BN_free(bn);

        if (hideNonMatches && !match) continue;

        cout << right << setw(INDEX_WIDTH) << i << ' '
             << left  << setw(PRIV_HEX_WIDTH) << privHex << ' '
             << setw(ADDR_WIDTH)  << address << ' '
             << setw(WIF_WIDTH)   << wif << ' '
             << right << setw(PCT_WIDTH) << pct << ' '
        << (match
                  ? string(ansi::GREEN) + "MATCH" + ansi::RESET
                  : string(ansi::RED) + "FAIL" + ansi::RESET)
             << '\n';
    }

    BN_CTX_free(ctx);
    return 0;
}

