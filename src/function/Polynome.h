#ifndef POLYNOME_H
#define POLYNOME_H

#include "Global.h"

// Utility classes
class Polynome {
   public:
    std::vector<unsigned char *> coef;

    Polynome(GlobalParameter& GP, const int threshold, element_t &secret);
    ~Polynome(); // add a destructor to free memory

    void print(GlobalParameter& GP);
    void evaluatePolynome(GlobalParameter& GP, element_t x, element_t &result);
    void evaluate_test(GlobalParameter& GP, element_t x, element_t &result);
};

#endif  // POLYNOME_H