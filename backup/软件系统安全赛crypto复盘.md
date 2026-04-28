十四号打的比赛 赛前没睡好觉，十五号又在考试，感觉自己要猝死了赶紧睡了一天，题目原文件在附录，现在来复盘这道题。
拿到压缩包有一个level1的文件夹和一个被加密的level2，level1里有10组c和20组pk，不管这那的先写个脚本提取一下en。
```python
from Crypto.PublicKey import RSA
ns = []
es = []
for i in range(20):
    with open(f'key-{i}.pem', 'rb') as f:
        key = RSA.import_key(f.read())
        ns.append(key.n)
        es.append(key.e)
print('e:', es)
print('n:', ns)
```
拿到参数之后再来看看出题脚本 思路很清晰了 大概就是拆开几组m，然后去CRT
其实我到这里就没在看具体rsa过程了 上面提取出来了小e和大e，直接喂给agent批量解。写wp的时候才发现encrypt里面出题人小巧思还用了aes流程，可惜被大运一般的claude创飞了。
```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
import gmpy2, owiener, math

keys = [RSA.import_key(open(f'key-{i}.pem', 'rb').read()) for i in range(20)]
ns = [k.n for k in keys]

fac = {}
for i in range(20):
    for j in range(i + 1, 20):
        g = math.gcd(ns[i], ns[j])
        if g not in (1, ns[i], ns[j]):
            fac[ns[i]] = (g, ns[i] // g)
            fac[ns[j]] = (g, ns[j] // g)

def dec(data, key):
    n, e = key.n, key.e
    kl = (n.bit_length() + 7) // 8
    if len(data) < kl + 28: return
    c = bytes_to_long(data[:kl])
    nonce, ct, tag = data[kl:kl + 12], data[kl + 12:-16], data[-16:]
    cs = []
    if e in (3, 5, 17, 257):
        r, ex = gmpy2.iroot(c, e)
        if ex:
            cs.append(int(r))
        else:
            for k in range(10000):
                r, ex = gmpy2.iroot(c + k * n, e)
                if ex: cs.append(int(r)); break
    if not cs and e.bit_length() > 10:
        d = owiener.attack(e, n)
        if d: cs.append(pow(c, d, n))
    if n in fac:
        p, q = fac[n]
        cs.append(pow(c, pow(e, -1, (p - 1) * (q - 1)), n))
    for m in set(cs):
        try:
            p = AES.new(long_to_bytes(m, 16), AES.MODE_GDDGCM, nonce=nonce).decrypt_and_verify(ct, tag)
            return p
        except:
            pass
ok = []
for i in range(1, 11):
    f = f'ciphertext-{i}.bin'
    d = open(f, 'rb').read()
    for j, key in enumerate(keys):
        r = dec(d, key)
        if r:
            open(f'dec_{i}_key{j}.txt', 'wb').write(r)
            ok.append(r)
            break

print(f'\n共{len(ok)}份明文')
```
<img width="416" height="70" alt="Image" src="https://github.com/user-attachments/assets/9050d1a8-3e37-4617-a65e-f6b7a13b1908" />

然后用这些构造CRT
```python
from math import gcd
from Crypto.Util.number import long_to_bytes, inverse

data = [ #太长了，自己跑一遍m吧]

def crt(a1, m1, a2, m2):
    g = gcd(m1, m2)
    lcm = m1 // g * m2
    t = ((a2 - a1) // g) * inverse(m1 // g, m2 // g) % (m2 // g)
    return (a1 + m1 * t) % lcm, lcm

rows = []
for d in data:
    rows.append([x.strip() for x in d.strip().splitlines()[1:]])

res = ''
for i in range(len(rows[0])):
    cong = []
    for r in rows:
        mod, rem, bits = r[i].split(':')
        cong.append((int(rem, 16), int(mod, 16)))
        bs = int(bits, 16)

    x, _ = cong[0]
    for a, m in cong[1:]:
        x, _ = crt(x, _, a, m)

    res += long_to_bytes(x).rjust(bs // 8, b'\x00').decode()

pwd = res.split('next pass is ')[1].split('\n')[0]
print(pwd)
```
9Zr4M1ThwVCHe4nHnmOcilJ8
拿这玩意打开level2 里面一个rsa出题一个加密的level3.
题目里写的很清楚d = getPrime(180)  
这个d太短了，考虑连分数攻击
ed ≡ 1 (mod φ(n)) 可知存在整数 k 使得 ed - kφ(n) = 1，变形可得 e/φ(n) ≈ k/d。
因为 φ(n) ≈ n，所以 e/n 的连分数展开中会出现 k/d 的近似。
```python
from hashlib import sha256
from math import gcd
from Crypto.Util.number import bytes_to_long, inverse

n = 99573363048275234764231402769464116416087010014992319221201093905687439933632430466067992037046120712199565250482197004301343341960655357944577330885470918466007730570718648025143561656395751518428630742587023267450633824636936953524868735263666089452348466018195099471535823969365007120680546592999022195781
e = 12076830539295193533033212232487568888200963123024189287629493480058638222146972496110814372883829765692623107191129306190788976704250502316265439996891764101447017190377014980293589797403095249538391534986638973035285900867548420192211241163778919028921502305790979880346050428839102874086046622833211913299
c1 = 88537483899519116785221065592618063396859368769048931371104532271282451393564912999388648867349770059882231896252136530442609316120059139869000411598215669228402275014417736389191093818032356471508269901358077592526362193180661405990147957408129845474938259771860341576649904811782733150222504695142224907008

m1 = bytes_to_long(b"Secret message: " + b"A" * 16)


def cf(num, den):
    while den:
        yield num // den
        num, den = den, num - (num // den) * den


def convs(cf):
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for a in cf:
        p2 = a * p1 + p0
        q2 = a * q1 + q0
        yield p2, q2
        p0, p1 = p1, p2
        q0, q1 = q1, q2


# 连分数攻击
for _, d in convs(cf(e, n)):
    for k in range(1, 9):
        if d % k:
            continue
        d2 = d // k
        if pow(c1, d2, n) == m1:
            print('d =', d2)

            # 分解n
            k2 = e * d2 - 1
            s = 0
            while k2 % 2 == 0:
                k2 //= 2
                s += 1

            for a in range(2, 200):
                x = pow(a, k2, n)
                if x in (1, n - 1):
                    continue
                for _ in range(s):
                    g = gcd(x - 1, n)
                    if 1 < g < n:
                        p, q = g, n // g
                        print('p =', p)
                        print('q =', q)
                        pwd = sha256(str(p + q).encode()).hexdigest()
                        print('pass =', pwd)
                        break
                    x = pow(x, 2, n)
                else:
                    continue
                break
            break
    else:
        continue
    break
```
这一层给出了 n  e  c 以及一个额外的 leak 值。 
 leak = ( (p * C1) ^ (q * C2) ^ ((p & q) << 64) ^ ((p | q) << 48) ^ ((p ^ q) * C3) ) + ((p + q) % MOD128) ^ ((p * q) & MASK64)
 由于所有运算都是线性的或位运算，leak 的低位只依赖于 p 和 q 的低位。因此可以从最低位开始递推：
```
from Crypto.Util.number import long_to_bytes, inverse

n = 3656543170780671302102369785821318948521533232259598029746397061108006818468053676291634112787611176554924353628972482471754519193717232313848847744522215592281921147297898892307445674335249953174498025904493855530892785669281622228067328855550222457290704991186404511294392428626901071668540517391132556632888864694653334853557764027749481199416901881332307660966462957016488884047047046202519520508102461663246328437930895234074776654459967857843207320530170144023056782205928948050519919825477562514594449069964098794322005156920839848615481717184615581471471105167310877784107653826948801838083937060929103306952084786982834242119877046219260840966142997264676014575104231122349770882974818427591538551719990220347345614399639643257685591321500648437402084919467346049683842042993975696447711080289559063959271045082506968532103445241637971734173037224394103944153692310048043693502870706225319787902231218954548412018259
e = 65537
c = 1757914668604154089701710446907445787512346500378259224658947923217272944211214757488735053484213917067698715050010452193463598710989123020815295814709518742755820383364097695929549366414223421242599840755441311771835982431439073932340356341636346882464058493459455091691653077847776771631560498930589569988646613218910231153610031749287171649152922929066828605655570431656426074237261255561129432889318700234884857353891402733791836155496084825067878059001723617690872912359471109888664801793079193144489323455596341708697911158942505611709946252101670450796550313079139560281843612045681545992626944803230832776794454353639122595107671267859292222861367326121435154862607517890329925621367992667728899878422037182817860641530146234730196633237339901726508906733897556146751503097127672718192958642776389691940671356367304182825433592577899881444815062581163386947075887218537802483045756886019426749855723715192981635971943
leak = 153338022210585970687495444409227961261783749570114993931231317427634321118309600575903662678286698071962304436931371977179197266063447616304477462206528342008151264611040982873859583628234755013757003082382562012219175070957822154944231126228403341047477686652371523951028071221719503095646413530842908952071610518530005967880068526701564472237686095043481296201543161701644160151712649014052002012116829110394811586873559266763339069172495704922906651491247001057095314718709634937187619890550086009706737712515532076

C1 = 0xDEADBEEFCAFEBABE123456789ABCDEFFEDCBA9876543210
C2 = 0xCAFEBABEDEADBEEF123456789ABCDEF0123456789ABCDEF
C3 = 0x123456789ABCDEFFEDCBA9876543210FEDCBA987654321


def leak_bits(p, q, k):
    x = ((p * C1) ^ (q * C2) ^ ((p & q) << 64) ^ ((p | q) << 48) ^ ((p ^ q) * C3))
    x = (x + ((p + q) % (1 << 128))) ^ (n & ((1 << 64) - 1))
    return x & ((1 << k) - 1)


# 从低位开始递推
states = [(1, 1)]
bits = n.bit_length() // 2

for i in range(1, bits):
    mod = 1 << (i + 1)
    new = []
    seen = set()
    tn = n & (mod - 1)
    tl = leak & (mod - 1)

    for pl, ql in states:
        for bp in (0, 1):
            for bq in (0, 1):
                pn = pl | (bp << i)
                qn = ql | (bq << i)

                if (pn * qn) & (mod - 1) != tn:
                    continue
                if leak_bits(pn, qn, i + 1) != tl:
                    continue
                if (pn, qn) not in seen:
                    seen.add((pn, qn))
                    new.append((pn, qn))

    states = new
    print(f'{i}: {len(states)}')

# 解密
p, q = states[0]
d = inverse(e, (p - 1) * (q - 1))
flag = long_to_bytes(pow(c, d, n)).decode()
print('flag =', flag)
```
出的真难 下次别这么出了，谢谢