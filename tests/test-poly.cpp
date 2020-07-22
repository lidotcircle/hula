#include <iostream>


struct A {
    int m_a;
    virtual ~A(){}
};
struct B: public A {};

void test1() {
    A* a = new B();
    delete a;

    B* b = dynamic_cast<decltype(b)>(a);
}

struct Base {
    inline virtual void hello() {std::cout << "hello world from Base" << std::endl;}
};
struct D1: virtual protected Base {
    void hello() override {std::cout << "hello c++ from D1" << std::endl;}
};
struct D2: virtual public Base {
    D2() {good();} // Call virtual method from constructor is extremly danger
    void good() {this->hello();}
};
struct D3: public D2 {
};
struct F: public D1, public D3 {};

void test2() {
    D2* p1 = new F();
    p1->good();
}

int main() //{
{
    test2();
    return 0;
} //}
