struct A {
    int m_a;
    virtual ~A(){}
};

struct B: public A {};

int main() //{
{
    A* a = new B();
    delete a;

    B* b = dynamic_cast<decltype(b)>(a);

    return 0;
} //}
