#pragma once

#include <unordered_map>
#include <type_traits>

#include <assert.h>


template<typename T1, typename T2>
class DuplexMap //{
{
    public:
        using TypeA = T1;
        using TypeB = T2;
        static_assert(!std::is_same<TypeA, TypeB>::value, "");


    private:
        using SMapA = std::unordered_map<TypeA, TypeB>;
        using SMapB = std::unordered_map<TypeB, TypeA>;

        friend class TypeAReference;
        friend class TypeBReference;
        class TypeAReference //{
        {
            private:
                DuplexMap& m_dmap;
                const TypeA& m_aa;
                TypeB* m_ab;


            public:
                inline TypeAReference(DuplexMap& map, const TypeA& val): m_dmap(map), m_aa(val) {
                    this->m_ab = nullptr;
                    if(this->m_dmap.m_mapa.find(this->m_aa) != this->m_dmap.m_mapa.end())
                        this->m_ab = &(this->m_dmap.m_mapa.find(this->m_aa)->second);
                }
                inline operator TypeB() {
                    if(this->m_ab != nullptr) return *this->m_ab;
                    else return TypeB();
                }
                inline TypeAReference& operator=(const TypeB& val) {
                    assert(this->m_dmap.m_mapb.find(val) == this->m_dmap.m_mapb.end());
                    if(this->m_ab != nullptr) {
                        TypeA bt = std::forward<TypeA>(this->m_dmap.m_mapb.find(*this->m_ab)->second);
                        assert(this->m_aa == bt);
                        this->m_dmap.m_mapb.erase(this->m_dmap.m_mapb.find(*this->m_ab));
                        this->m_dmap.m_mapb[val] = bt;
                        *this->m_ab = val;
                    } else {
                        assert(this->m_dmap.m_mapa.find(this->m_aa) == this->m_dmap.m_mapa.end());
                        this->m_dmap.m_mapa[this->m_aa] = val;
                        this->m_dmap.m_mapb[val] = this->m_aa;
                        this->m_ab = &this->m_dmap.m_mapa.find(this->m_aa)->second;
                    }
                    return *this;
                }
        }; //}
        class TypeBReference //{
        {
            private:
                DuplexMap& m_dmap;
                const TypeB& m_bb;
                TypeA* m_ba;


            public:
                inline TypeBReference(DuplexMap& map, const TypeB& val): m_dmap(map), m_bb(val) {
                    this->m_ba = nullptr;
                    if(this->m_dmap.m_mapb.find(this->m_bb) != this->m_dmap.m_mapb.end())
                        this->m_ba = &this->m_dmap.m_mapb.find(this->m_bb)->second;
                }
                inline operator TypeA() {
                    if(this->m_ba != nullptr) return *this->m_ba;
                    else return TypeA();
                }
                inline TypeBReference& operator=(const TypeA& val) {
                    assert(this->m_dmap.m_mapa.find(val) == this->m_dmap.m_mapa.end());
                    if(this->m_ba != nullptr) {
                        TypeB bt = std::forward<TypeB>(this->m_dmap.m_mapa.find(*this->m_ba)->second);
                        assert(this->m_bb == bt);
                        this->m_dmap.m_mapa.erase(this->m_dmap.m_mapa.find(*this->m_ba));
                        this->m_dmap.m_mapa[val] = bt;
                        *this->m_ba = val;
                    } else {
                        assert(this->m_dmap.m_mapb.find(this->m_bb) == this->m_dmap.m_mapb.end());
                        this->m_dmap.m_mapb[this->m_bb] = val;
                        this->m_dmap.m_mapa[val] = this->m_bb;
                        this->m_ba = &this->m_dmap.m_mapb.find(this->m_bb)->second;
                    }
                    return *this;
                }
        }; //}


    public:
        using iterator = typename SMapA::iterator;


    private:
        SMapA m_mapa;
        SMapB m_mapb;


    public:
        DuplexMap();

        iterator find(TypeA obj);
        iterator find(TypeB obj);

        void push_back(TypeA obj1, TypeB obj2);
        void erase(iterator);

        const iterator begin();
        const iterator end();
        inline const iterator cbegin() {return this->begin();}
        inline const iterator cend()   {return this->end();}

        TypeAReference operator[](const TypeA&);
        TypeBReference operator[](const TypeB&);

        bool   empty();
        size_t size();
}; //}


template<typename T1, typename T2>
DuplexMap<T1, T2>::DuplexMap(): m_mapa(), m_mapb() {}

template<typename T1, typename T2>
typename DuplexMap<T1, T2>::iterator DuplexMap<T1, T2>::find(TypeA obj) //{
{
    return this->m_mapa.find(obj);
} //}
template<typename T1, typename T2>
typename DuplexMap<T1, T2>::iterator DuplexMap<T1, T2>::find(TypeB obj) //{
{
    if(this->m_mapb.find(obj) == this->m_mapb.end())
        return this->m_mapa.end();
    auto obja = this->m_mapb[obj];
    return this->m_mapa.find(obja);
} //}

template<typename T1, typename T2>
void DuplexMap<T1, T2>::push_back(TypeA oa, TypeB ob) //{
{
    assert(this->m_mapa.find(oa) == this->m_mapa.end());
    assert(this->m_mapb.find(ob) == this->m_mapb.end());

    this->m_mapa[oa] = ob;
    this->m_mapb[ob] = oa;
} //}
template<typename T1, typename T2>
void DuplexMap<T1, T2>::erase(iterator iter) //{
{
    assert(iter != this->end());
    this->m_mapb.erase(this->m_mapb.find(iter->second));
    this->m_mapa.erase(this->m_mapa.find(iter->first));
} //}

template<typename T1, typename T2>
const typename DuplexMap<T1, T2>::iterator DuplexMap<T1, T2>::begin() //{
{
    return this->m_mapa.begin();
} //}
template<typename T1, typename T2>
const typename DuplexMap<T1, T2>::iterator DuplexMap<T1, T2>::end() //{
{
    return this->m_mapa.end();
} //}

template<typename T1, typename T2>
typename DuplexMap<T1, T2>::TypeAReference DuplexMap<T1, T2>::operator[](const TypeA& val) //{
{
    return TypeAReference(*this, val);
} //}
template<typename T1, typename T2>
typename DuplexMap<T1, T2>::TypeBReference DuplexMap<T1, T2>::operator[](const TypeB& val) //{
{
    return TypeBReference(*this, val);
} //}

template<typename T1, typename T2>
size_t DuplexMap<T1, T2>::size() {assert(this->m_mapa.size() == this->m_mapb.size()); return this->m_mapa.size();}
template<typename T1, typename T2>
bool DuplexMap<T1, T2>::empty() {return this->size() == 0;}

