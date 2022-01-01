#include <stdio.h>


int test(int a) {
    int arr[5] = {0, 1, 2, 3, 4};
    int b = arr[a];
    printf("%d", b);
    return b;
}
int main() {
    test(5);
    return 0;
}
