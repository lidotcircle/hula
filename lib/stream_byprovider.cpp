#include "../include/stream_byprovider.h"

void NotImplement() {assert(false && "not implement");}

bool EBStreamByProvider::bind(struct sockaddr* addr) {NotImplement(); return false;}
bool EBStreamByProvider::listen() {NotImplement(); return false;}
bool EBStreamByProvider::accept(void*, void*) {NotImplement(); return false;}


