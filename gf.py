# -*- coding: utf-8 -*-
import time

class G_F:
    """
    Genera un cuerpo finito usando como polinomio irreducible el dado
    representado como un entero. Por defecto toma el polinomio del AES.
    Los elementos del cuerpo los representaremos por enteros 0<= n <= 255.
    """

    def __init__(self, Polinomio_Irreducible = 0x11B):
        """
        Entrada: un entero que representa el polinomio para construir el cuerpo
        Tabla_EXP y Tabla_LOG dos tablas, la primera tal que en la posicion
        i-esima tenga valor a=g**i y la segunda tal que en la posicion a-esima
        tenga el valor i tal que a=g**i. (g generador del cuerpo finito
        representado por el menor entero entre 0 y 255.)
        """
        self.Polinomio_Irreducible = Polinomio_Irreducible
        self.g = self.get_generador()
        self.get_tablas()

    def get_generador(self):
        #Optimizacion con factores primos (255 = 3 * 5 * 17)
        factores_primos = [3, 5, 17]
        for g in range(2, 256):
            es_generador = True
            for p in factores_primos:
                if self.potencia(g, 255 // p) == 1:
                    es_generador = False
                    break
            if es_generador:
                return g

    #Se puede optimizar mas
    def potencia(self, base, exp):
        resultado = 1
        for i in range(exp):
            resultado = self.productoPolinomio(resultado, base)
        return resultado

    def get_tablas(self):
        self.Tabla_EXP = [0] * 255  # Inicializamos con 255 posiciones
        self.Tabla_LOG = [-1] * 256  # 256 posiciones, -1 para 0 o no definido
        valor = 1  # g^0 = 1
        self.Tabla_EXP[0] = valor
        self.Tabla_LOG[valor] = 0
        

        for i in range(1, 255):
            valor = self.xTimes(valor) if self.g == 2 else self.productoPolinomio(valor, self.g)
            self.Tabla_EXP[i] = valor
            self.Tabla_LOG[valor] = i
        
    
    def xTimes(self, n):
        """
        Entrada: un elemento del cuerpo representado por un entero entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de 'n' y 0x02 (el polinomio X).
        """
        bit7 = n & 0x80
        n <<= 1 #Multiplicar por x(2)
        if bit7: 
            n ^= self.Polinomio_Irreducible #Si hay mas de 8 bits reducir modulo del polinomio
        return n & 0xFF
        

    def productoPolinomio(self, a, b):
        """
        Entrada: dos elementos del cuerpo representados por enteros entre 0 y 255
        Salida: un elemento del cuerpo representado por un entero entre 0 y 255
        que es el producto en el cuerpo de la entrada.
        Atencion: Se valorara la eficiencia. No es lo mismo calcularlo
        usando la definicion en terminos de polinomios o calcular
        usando las tablas Tabla_EXP y Tabla_LOG.
        """
        # Version polinomios
        if a == 0 or b == 0:
            return 0
        
        res = 0
        for i in range(8):
            if b & 1:
                res ^= a #Sumar al resultado
            a = self.xTimes(a) #Multiplcar a * x
            b >>= 1 #Mirar siguiente bit
        return res
    
    def producto(self, a, b):
        if a == 0 or b == 0:
            return 0
        res = (self.Tabla_LOG[a] + self.Tabla_LOG[b]) % 255
        return self.Tabla_EXP[res]

    def inverso(self, n):
        """
        Entrada: un elementos del cuerpo representado por un entero entre 0 y 255
        Salida: 0 si la entrada es 0,
        el inverso multiplicativo de n representado por un entero entre
        1 y 255 si n <> 0.
        Atencion: Se valorara la eficiencia.
        """
        if n == 0:
            return 0
        res = (255 - self.Tabla_LOG[n]) % 255
        return self.Tabla_EXP[res]

    def mostrar_info(self):
            print("=" * 50)
            print("🔹 Información del cuerpo finito GF(2^8)")
            print("=" * 50)
            print(f"Polinomio irreducible: {self.Polinomio_Irreducible:#04x} ({self.Polinomio_Irreducible})")
            print(f"Forma binaria: {self.Polinomio_Irreducible:#011b}")
            print(f"Generador encontrado: g = {self.g:#04x} ({self.g})")
            print("-" * 50)

            print("🔸 Tabla EXP (g^i):")
            for i in range(0, 255, 16):
                fila = self.Tabla_EXP[i:i+16]
                print(" ".join(f"{x:02X}" for x in fila))
            print("-" * 50)

            print("🔸 Tabla LOG (log_g(a)):")
            for i in range(0, 256, 16):
                fila = self.Tabla_LOG[i:i+16]
                print(" ".join(f"{x:3}" for x in fila))
            print("=" * 50)


if __name__ == "__main__":
    inicio = time.time()
    gf = G_F(0x11B)
    fin = time.time()
    gf.mostrar_info()
  
    print(f"Producto polinómico 0x57 * 0x83 = {gf.productoPolinomio(0x57, 0x83):02X}")
    print(f"Producto con tablas  0x57 * 0x83 = {gf.producto(0x57, 0x83):02X}")
    print(f"Inverso de 0x57 = {gf.inverso(0x57):02X}")
    print(f"Tiempo de ejecución: {fin - inicio:.6f} segundos")
