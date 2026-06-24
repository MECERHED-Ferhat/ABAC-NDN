#include "Polynome.h"

/**
 * @brief Converts a given PBC element to a byte representation and stores it in
 * a buffer.
 *
 * @param elt The PBC element to be converted.
 * @param buffer A vector of unsigned char pointers where the byte
 * representation will be stored.
 * @param position The position in the buffer where the conversion should start.
 * @param ARRAY_SIZE The size of the array to be used for the conversion.
 */
void convertToByte(element_t &elt, std::vector<unsigned char *> &buffer,
    const int position, const int ARRAY_SIZE);

// Utility classes
Polynome::Polynome(GlobalParameter& GP, const int threshold, element_t &secret) {
    element_t tmp;
    element_init_Zr(tmp, GP.e);

    convertToByte(secret, coef, -1, BUFFER_SIZE["ZN"]);    

    for (int i = 1; i < threshold; i++) {
        element_random(tmp);
        convertToByte(tmp, coef, -1, BUFFER_SIZE["ZN"]);
    }

    element_clear(tmp);
}

Polynome::~Polynome() {
    for (auto ptr : coef) {
        delete[] ptr;
    }
}

void Polynome::print(GlobalParameter& GP) {
    element_t tmp;
    element_init_Zr(tmp, GP.e);

    for (size_t i = 0; i < coef.size(); i++) {
        element_from_bytes(tmp, coef[i]);
        element_printf("Coef[%d] = %B\n", i, tmp);
    }

    element_clear(tmp);
}

void Polynome::evaluatePolynome(GlobalParameter& GP, element_t x,
                                element_t &result) {
    element_t tmp1, tmp2, tmp3, tmp4, index;
    element_init_Zr(index, GP.e);
    element_init_Zr(tmp1, GP.e);
    element_init_Zr(tmp2, GP.e);
    element_init_Zr(tmp3, GP.e);
    element_init_Zr(tmp4, GP.e);

    element_from_bytes(tmp1, coef[0]);

    element_set(result, tmp1);

    for (int i = 1; i < coef.size(); i++) {
        element_from_bytes(tmp1, coef[i]);
        element_set_si(index, i);
        element_pow_zn(tmp2, x, index);
        element_mul(tmp3, tmp2, tmp1);
        element_set(tmp4, result);
        element_add(result, tmp4, tmp3);
    }

    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
    element_clear(tmp4);
    element_clear(index);
}

void Polynome::evaluate_test(GlobalParameter& GP, element_t x,
                             element_t &result) {
    element_t tmp1, tmp2, tmp3, tmp4, index;
    element_init_Zr(index, GP.e);
    element_init_Zr(tmp1, GP.e);
    element_init_Zr(tmp2, GP.e);
    element_init_Zr(tmp3, GP.e);
    element_init_Zr(tmp4, GP.e);

    element_set1(result);

    for (int i = 1; i < coef.size(); i++) {
        element_set1(tmp1);
        element_set_si(index, i);
        element_pow_zn(tmp2, x, index);
        element_mul(tmp3, tmp2, tmp1);
        element_set(tmp4, result);
        element_add(result, tmp4, tmp3);
    }

    element_clear(tmp1);
    element_clear(tmp2);
    element_clear(tmp3);
    element_clear(tmp4);
    element_clear(index);
}
