import struct

# Constantes para o algoritmo SHA-256
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Funções auxiliares para o SHA-256
def right_rotate(value, count):
    """
    Rotaciona o valor para a direita pelo número de bits especificado.
    
    value: O valor a ser rotacionado.
    count: O número de bits a rotacionar.
    
    Retorna o valor rotacionado.
    """
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF

def sha256_transform(chunk, H):
    """
    Realiza a transformação SHA-256 em um único bloco de 512 bits.
    
    chunk: O bloco de 512 bits.
    H: Os valores hash iniciais.
    
    Atualiza os valores hash com a transformação.
    """
    # Quebrar o bloco em palavras de 32 bits
    w = list(struct.unpack('>16L', chunk)) + [0] * 48

    # Estender as palavras para 64 palavras
    for i in range(16, 64):
        s0 = right_rotate(w[i-15], 7) ^ right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = right_rotate(w[i-2], 17) ^ right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF

    # Inicializar os valores de trabalho com os hash valores atuais
    a, b, c, d, e, f, g, h = H

    # Comprimir as palavras
    for i in range(64):
        S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
        S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF

    # Adicionar a transformação atual aos hash valores
    H[0] = (H[0] + a) & 0xFFFFFFFF
    H[1] = (H[1] + b) & 0xFFFFFFFF
    H[2] = (H[2] + c) & 0xFFFFFFFF
    H[3] = (H[3] + d) & 0xFFFFFFFF
    H[4] = (H[4] + e) & 0xFFFFFFFF
    H[5] = (H[5] + f) & 0xFFFFFFFF
    H[6] = (H[6] + g) & 0xFFFFFFFF
    H[7] = (H[7] + h) & 0xFFFFFFFF

# Função principal para calcular o hash SHA-256
def sha256(data):
    """
    Calcula o hash SHA-256 de uma entrada.
    
    data: Os dados de entrada.
    
    Retorna o hash SHA-256 em formato hexadecimal.
    """
    # Inicializar os valores hash
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # Preprocessamento: adicionar um bit '1' e preencher com zeros
    data = bytearray(data, 'utf-8')  # Converter a entrada em bytes
    orig_len_in_bits = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)

    # Adicionar o comprimento original em bits no final da mensagem
    data += orig_len_in_bits.to_bytes(8, 'big')

    # Processar a mensagem em blocos de 512 bits
    for i in range(0, len(data), 64):
        sha256_transform(data[i:i+64], H)

    # Produzir o hash final como uma string hexadecimal
    return ''.join(f'{x:08x}' for x in H)

# Função para verificar se um texto corresponde a um hash fornecido
def verify_hash(text, provided_hash):
    """
    Verifica se o hash fornecido foi gerado a partir de um texto.
    
    text: O texto original.
    provided_hash: O hash fornecido.
    
    Retorna True se o hash fornecido corresponder ao hash calculado a partir do texto, caso contrário False.
    """
    # Calcular o hash do texto fornecido
    calculated_hash = sha256(text)
    
    # Comparar o hash calculado com o hash fornecido
    return calculated_hash == provided_hash

# Exemplo de uso
if __name__ == "__main__":
    """
    Exemplo de uso:

    - Calcular o hash SHA-256 de uma string de entrada.
    - Verificar se o hash corresponde ao texto fornecido.
    - Mostrar o valor do hash resultante em formato hexadecimal.
    """
    # Dados de entrada
    data = "Mensagem para calcular o hash"
    
    # Calcular o hash SHA-256
    hash_result = sha256(data)
    
    # Mostrar o resultado
    print(f"Entrada: {data}")
    print(f"Hash SHA-256: {hash_result}")
    
    # Verificar se o hash corresponde ao texto fornecido
    is_valid = verify_hash(data, hash_result)
    print(f"O hash fornecido corresponde ao texto? {is_valid}")
    
    # Testar com um hash incorreto
    incorrect_hash = "abcdef1234567890"
    is_valid = verify_hash(data, incorrect_hash)
    print(f"O hash incorreto corresponde ao texto? {is_valid}")
