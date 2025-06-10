# Basics
```cpp
// Simple comment

/* 
This is a bit long comment
Also a newline in a long comment
*/
```
## Shitty Printing
```cpp
std::cout << i << "+" << j << "=" << somme(i, j) << endl;
```

## I/O streams

```cpp
#include <iostream>

/*
Code snippet...
*/

cin >> variable_name;
cout << variable_name << endl;
```

## Scope Resolution Operator ::
```cpp
#include <iostream>

using namespace std;
int i = 209; // Global variable i

int main()
{
    int i = 37; // Local variable i in main
    {
        int i = 9; // Local variable i in inner block
        ::i = ::i + 1; // Refers to the global i (209), so now global i = 210
        cout << ::i << " " << i << endl; // Outputs: 210 9
    }
    cout << ::i << " " << i << endl; // Outputs: 210 37
}

```

## Pointer/ Reference

They end up with the same disassembly code. Just a shitty pointer with a layer of security and non-nullability.


![[cpp-shit1.png]]


![[cpp-shit2.png]]

Simple pass the references of the variables and it will change it.
```cpp
#include <iostream>

using namespace std;

void permuter(int &a, int &b) {
	int w;
	w = a;
	a = b;
	b = w;
}

int main(){
	int x = 45, y = 50;
	permuter(x, y);
	std::cout << "x = " << x << endl;
	return 0;
}
```

To protect valuable variables, use the `const` word to preserve the important asset.
```cpp
struct INFO { 
	char nom[30], 
	prenom[20],
	mail[256]; 
};

void affiche( const INFO & f) { 
	cout << f.nom << " " << f.prenom; cout << " " << f.adresse << endl; 
} 

int main() { 
	INFO user = {"Ali", "Salah", "ali.salah@enit.rnu.tn"}; 
	affiche(user); 
}
```

## Memory Allocation

### new, delete
```cpp
int *ptr1, *ptr2, *ptr3;

ptr1 = new int;
ptr2 = new int[10];
ptr3 = new int(10); // Initialized to 10

struct date{
	int jour, mois, an;
};

date *ptr4, *ptr5, *ptr6, d = {25, 4, 1954}; // d is allocated on the stack.
// d dfield values are put on the stack one by one.

ptr4 = new date; // Allocated on the heap using the new operator
ptr5 = new date[10]; // Allocated an array of 10 date objects using new.
ptr6 = new date(d); // Copies the content of d object using MOV instructions.

delete ptr4; // Free the space allocated by an object.
delete[] ptr5; // Frees the space used by an array of objects.
delete ptr6;    
```


## inline suggestion

Used for the cases where the work of the function is simpler than the overhead of the calling convention and work done by the process. When performing a simple addition, it is simpler to do it without going through all the stack work. So inline comes in handy in these situations where it will save you some costs.
It is a suggestion not an obligation, the compiler might ignore it in many cases: there is a recursive function, static variables, loops...etc
So in conclusion instead of doing the stack work, it'll replace its code whenever it is met.

## Function Overloading
### Signature

A function signature is the combination of:
- The function's name
- The number and types of its parameters
- The order of the parameters
The return type, the parameter names and the default values are NOT included. 
```cpp
int sum(int a, int b){...};
int sum(int a, int b, int c){...};
double sum(double a, double b, double c){...};

double sum(int a, int b){...}; // This results in an error, because the return type is NOT included in the signature. This conflicts with the first line
```

#### Assembly
To get even lower, according to "the calling convention", here how calling the first sum function should look like:
```cpp
sum(1, 2);
```

```assembly
<SOME STACK FRAME ALIGNEMENT>

mov rsi, 0x2 
mov rdi, 0x1
call sum
```
So as we can see, this didn't include the anything related to the return type, so after the call function, the processor finds itself with two addresses of functions to execute. This is dangerous (CTF challenge/Vulnerable compiler Project idea).

#### Name Mangling
Name mangling is the process by which a compiler **encodes** function names and their types (like parameters and return type) into a **unique string** for each function. This is done to **distinguish overloaded functions** and functions with different signatures.

```cpp
#include <iostream>

int sum(int a, int b) {
    return a + b;
}

double sum(double a, double b) {
    return a + b;
}

int main() {
    std::cout << sum(3, 4) << std::endl;
    std::cout << sum(3.0, 4.0) << std::endl;
    return 0;
}
```

```bash
$g++ -c mangle.cpp -o mangle.o // compile to object file

$nm mangle.o
                 U _GLOBAL_OFFSET_TABLE_
000000000000002e T main
0000000000000014 T _Z3sumdd // dd for double parameters
0000000000000000 T _Z3sumii // ii for int parameters
<SNIP...>
```

# OOP
## Classes
```cpp
class person {
	
	// Attributes
	String name;
	String address;
	String age;
	
	// Methods
	void walk(){...};
	void run(){...};
	void live(){...};
}
```
## Visibility
- **Public**: Members declared as `public` are accessible from **any part of the program**, including code outside the class.
- **Private**: Members declared as `private` are accessible **only within the class** they are defined in. They cannot be accessed from outside the class or from derived classes. But can be accessed with public functions.
- **Protected**: Members declared as `protected` are accessible **within the class** and **by derived (child) classes**, but **not** from outside the class hierarchy.

## Constant functions

These functions cannot modify the object's state.

```cpp
class MyClass {
public:
    int data;

    MyClass(int val) : data(val) {}

    // Constant function
    int getData() const {
        return data;
    }

    // Attempting to modify any member variable within this function would result in a compile-time error
    void printData() const {
        std::cout << "Data: " << data << std::endl;
        // data = 100; // This would cause a compile-time error
    }
};

```