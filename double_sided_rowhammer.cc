// Copyright 2015, Google, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Small test program to systematically check through the memory to find bit
// flips by double-sided row hammering.
//
// Compilation instructions:
//   g++ -std=c++11 [filename]
//
// ./double_sided_rowhammer [-t nsecs] [-p percentage]
//
// Hammers for nsecs seconds, acquires the described fraction of memory (0.0
// to 0.9 or so).
//
// Original author: Thomas Dullien (thomasdullien@google.com)

#include <asm/unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kernel-page-flags.h>
#include <map>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <vector>

//PAGE_SIZE 0x1000


namespace {

// The fraction of physical memory that should be mapped for testing.
double fraction_of_physical_memory = 0.3;

// The time to hammer before aborting. Defaults to one hour.
uint64_t number_of_seconds_to_hammer = 3600;

// The number of memory reads to try.
uint64_t number_of_reads = 1000*1024;

// Obtain the size of the physical memory of the system.
uint64_t GetPhysicalMemorySize() {
  struct sysinfo info;
  sysinfo( &info );
  return (size_t)info.totalram * (size_t)info.mem_unit;
}

// aqui vamos ler o pagemap, e nos deslocar para o bit 54 no buffer
uint64_t GetPageFrameNumber(int pagemap, uint8_t* virtual_address) { // page frame = 4KB (diff page table = page table eh a lista ligada de ponteiros a page frame)
    // recebe ponteiro a descritor pagemap e o mapeamento de memoria
  // Read the entry in the pagemap. /****
  uint64_t value; 
  int got = pread(pagemap, &value, 8,
                  (reinterpret_cast<uintptr_t>(virtual_address) / 0x1000) * 8); // lee o descritor sem avançar seek, &value = buffer de 64bits 8 bytes, e le offset 
  assert(got == 8); // lidos 8 byte 64 bits
  uint64_t page_frame_number = value & ((1ULL << 54)-1); ((inteiro positivo de 64b << (deslocamento para a esquerda no indice da mascara buffer 54 -1)  
  return page_frame_number; // retorna a mascara de bit (54..64) no pagemap
}

void SetupMapping(uint64_t* mapping_size, void** mapping) { 
  *mapping_size = 
    static_cast<uint64_t>((static_cast<double>(GetPhysicalMemorySize()) * 
          fraction_of_physical_memory)); // tamanho total * pedaço da memoria que designamos 

  *mapping = mmap(NULL, *mapping_size, PROT_READ | PROT_WRITE, 
      MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); // If addr is NULL, then the kernel chooses the (page-aligned)
      // address at which to create the mapping, pedaço da memoria,RW , gera uma prefault para que o kernel carrega a pagina de memoria, pagina privada, iniciliazdo como um mapeamento 0 sem respaldo de um descritor, 0)
  assert(*mapping != (void*)-1); // verifica que o mapeamento foi feito

  
  
  // we first deliberately fragment physical memory so that the kernel’s allocations from physical memory are randomised: // FAILURE PRE



  

  // Initialize the mapping so that the pages are non-empty.
  printf("[!] Initializing large memory mapping ...");
  for (uint64_t index = 0; index < *mapping_size; index += 0x1000) {
    uint64_t* temporary = reinterpret_cast<uint64_t*>(
        static_cast<uint8_t*>(*mapping) + index);
    temporary[0] = index;
  }
  printf("done\n");
}
// ate aqui, foi lido o tamanho total da memoria, foram definidas variaveis pra alocar 1gb, e foram mapeadas com flags -> prefault e foram carregados dados no mapeamento

uint64_t HammerAddressesStandard(
    const std::pair<uint64_t, uint64_t>& first_range, // constante do tipo 64bits, pode conter ateh 2 (pair) {64_t, 64_t}
    const std::pair<uint64_t, uint64_t>& second_range, // a funçao vai receber dois endereços de 64 bits e e um inteiro de tentativas (read)
    uint64_t number_of_reads) 
{
  volatile uint64_t* first_pointer = // ponteiro volatil de endereço 
      reinterpret_cast<uint64_t*>(first_range.first); //você está convertendo um ponteiro para um tipo de dado arbitrário em um ponteiro para um inteiro de 64 bits
  volatile uint64_t* second_pointer =
      reinterpret_cast<uint64_t*>(second_range.first); // converte os dois endereços passados como um dado, para ponteiro de 64bits
  uint64_t sum = 0; 

  while (number_of_reads-- > 0) { // aqui ele começaram a iterar no parametro de leituras ateh que seja igual a 0
    sum += first_pointer[0]; // sum = 0 + ponteiro[primeiro endereço passado pelo parametro 64_t]
    sum += second_pointer[0];
    asm volatile( // exploit que limpa o cache e recarrega as celulas do endereço
        "clflush (%0);\n\t"
        "clflush (%1);\n\t"
        : : "r" (first_pointer), "r" (second_pointer) : "memory");
  }
  return sum; //retorna sum
} //fim do nucleo do exploit -> carregar e descarregar as celulas da linha (endereço)

typedef uint64_t(HammerFunction)( //struct definido os tipos de dados membros
    const std::pair<uint64_t, uint64_t>& first_range,
    const std::pair<uint64_t, uint64_t>& second_range,
    uint64_t number_of_reads);

// A comprehensive test that attempts to hammer adjacent rows for a given 
// assumed row size (and assumptions of sequential physical addresses for 
// various rows.
uint64_t HammerAllReachablePages(uint64_t presumed_row_size, // suposto row
    void* memory_mapping, uint64_t memory_mapping_size, HammerFunction* hammer,
    uint64_t number_of_reads) {
  // This vector will be filled with all the pages we can get access to for a
  // given row size.
  std::vector<std::vector<uint8_t*>> pages_per_row; //vetor de vetores de ponteiros a 1 byte (page), lista ligada de paginas de mem
  uint64_t total_bitflips = 0; //64bits inteiro

  pages_per_row.resize(memory_mapping_size / presumed_row_size); // oresize vetor de vetor de ponteiros ( porcentagem da mem / suposto tamanho das row) pra assim definir as paginas por row
  int pagemap = open("/proc/self/pagemap", O_RDONLY); // descritor pagemap **
  assert(pagemap >= 0);

  printf("[!] Identifying rows for accessible pages ... "); //identificando row por paginas 
  for (uint64_t offset = 0; offset < memory_mapping_size; offset += 0x1000) { // for(64b_ i = 0; i < porcentagem da memoria; i+=0x1000) 
    uint8_t* virtual_address = static_cast<uint8_t*>(memory_mapping) + offset; //8b virtual addr = converte[8b*](ponteiro a memoria mapeada + 0x1000) = virtual addr = 8b*(mmap*+0x1000)
    uint64_t page_frame_number = GetPageFrameNumber(pagemap, virtual_address); //  retorna os bits 54..65 no descritor pagemap (obtem o quadro de mem)
    uint64_t physical_address = page_frame_number * 0x1000; // multiplica o quadro de mem por 0x1000 para obter o endereço fisico ( desloca 2 posições pra converter em endereço)
    uint64_t presumed_row_index = physical_address / presumed_row_size; // endereço fisico / tamanho de row = index(index dos row baseado na divisao entre o endereço fisico e o tamanho dos row)
    
    //printf("[!] put virtualaddr %lx phyaddr %lx int row %ld\n", (uint64_t)virtual_address,
    //    physical_address, presumed_row_index); //**
    
    
    if (presumed_row_index > pages_per_row.size()) {  // index > vetor 
      pages_per_row.resize(presumed_row_index); // aumenta o tamanho do vetor
    }
    pages_per_row[presumed_row_index].push_back(virtual_address); // adiciona endereço virtual ao final do vetor
    //printf("[!] done\n");
  }
  printf("Done\n");
  

  // We should have some pages for most rows now.
  for (uint64_t row_index = 0; row_index + 2 < pages_per_row.size();  //i = 0; i +2 ; i < tamanho do vetor; ++i
      ++row_index) {
        // se nao encontra attacker, victim, attacker na lista ligada de paginas de memoria por row (ponteiro), finaliza, se for o fim do row, finaliza
    if ((pages_per_row[row_index].size() != 64) ||  // size(paginas por row[ponteiro na posição 0 ou 2]) ! 64) 
        (pages_per_row[row_index+2].size() != 64)) { // le a lista ligada procurando 3 endereços (attacker, victim, attacker)
      printf("[!] Can't hammer row %ld - only got %ld/%ld pages " 
          "in the rows above/below\n", // fim da lista
          row_index+1, pages_per_row[row_index].size(), 
          pages_per_row[row_index+2].size());

      
      continue;
    } else if (pages_per_row[row_index+1].size() == 0) { // nao encontrap aginas
      printf("[!] Can't hammer row %ld, got no pages from that row\n", 
          row_index+1);
      continue;
    }
    printf("[!] Hammering rows %ld/%ld/%ld of %ld (got %ld/%ld/%ld pages)\n",  //ENCONTROU OS ENDEREÇOS E COMEÇARA A ROUTINA DE HAMMER
        row_index, row_index+1, row_index+2, pages_per_row.size(), 
        pages_per_row[row_index].size(), pages_per_row[row_index+1].size(), 
        pages_per_row[row_index+2].size());

        
    // Iterate over all pages we have for the first row. 
        
    for (uint8_t* first_row_page : pages_per_row[row_index]) { // aqui selecionamos a wordline 0
      
      // itera sobre as paginas do primeiro row
      
      // Iterate over all pages we have for the second row.
      //second
      for (uint8_t* second_row_page : pages_per_row[row_index+2]) { // a wordline 2
        
        
        // Set all the target pages to 0xFF. // 0xFF physic mem 
        for (uint8_t* target_page : pages_per_row[row_index+1]) {  // aqui selecionamos a wordline 1, a vitima
          memset(target_page, 0xFF, 0x1000); //  enxe a pagina vitima em FF para verificar se houve mudança 
        }
        
        // Now hammer the two pages we care about. //ATTACK
        std::pair<uint64_t, uint64_t> first_page_range( 
            reinterpret_cast<uint64_t>(first_row_page), 
            reinterpret_cast<uint64_t>(first_row_page+0x1000));
        std::pair<uint64_t, uint64_t> second_page_range(
            reinterpret_cast<uint64_t>(second_row_page),
            reinterpret_cast<uint64_t>(second_row_page+0x1000));
        hammer(first_page_range, second_page_range, number_of_reads); //HAMMER (first page, second page, number of asm routine clflush)
        // Now check the target pages.
        uint64_t number_of_bitflips_in_target = 0;      //verifica bitflips
        for (const uint8_t* target_page : pages_per_row[row_index+1]) { // verifica wordline victim
          for (uint32_t index = 0; index < 0x1000; ++index) { // i < 0x1000 (tamanho de addr em x64), ++i
            if (target_page[index] != 0xFF) { // verifica se houve mudança BITFLIP ou seja, se eh diferente de FF (line 200)
              ++number_of_bitflips_in_target; // aumenta contagem de flips se houver
            }
          }
        }
        if (number_of_bitflips_in_target > 0) { //se bitflips for maior que 0
          printf("[!] Found %ld flips in row %ld (%lx to %lx) when hammering "  ///////ENCONTRAMOS UMA WORDLINE SUSCETIVEL
              "%lx and %lx\n", number_of_bitflips_in_target, row_index+1,
              ((row_index+1)*presumed_row_size), 
              ((row_index+2)*presumed_row_size)-1,
              GetPageFrameNumber(pagemap, first_row_page)*0x1000, //endereço fisico extraido de pagemap comparado com endereço virtual da lista ligada
              GetPageFrameNumber(pagemap, second_row_page)*0x1000);
          total_bitflips += number_of_bitflips_in_target; 
        }
      }
    }
  }
  return total_bitflips;
}







void HammerAllReachableRows(HammerFunction* hammer, uint64_t number_of_reads) { // recebe como ponteiro o nucleo do exploit e 1gb e as vezes de leitura, aqui iremos fazer o mapeamento 
  uint64_t mapping_size; 
  void* mapping;
  SetupMapping(&mapping_size, &mapping); // tamanho do mapeamento e 

  HammerAllReachablePages(1024*256, mapping, mapping_size,
                          hammer, number_of_reads);
}

void HammeredEnough(int sig) {
  printf("[!] Spent %ld seconds hammering, exiting now.\n",
      number_of_seconds_to_hammer);
  fflush(stdout);
  fflush(stderr);
  exit(0);
}

}  // namespace

int main(int argc, char** argv) {
  // Turn off stdout buffering when it is a pipe.
  setvbuf(stdout, NULL, _IONBF, 0);

  int opt;
  while ((opt = getopt(argc, argv, "t:p:")) != -1) {
    switch (opt) {
      case 't':
        number_of_seconds_to_hammer = atoi(optarg);
        break;
      case 'p':
        fraction_of_physical_memory = atof(optarg);
        break;
      default:
        fprintf(stderr, "Usage: %s [-t nsecs] [-p percent]\n", 
            argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  signal(SIGALRM, HammeredEnough);

  printf("[!] Starting the testing process...\n");
  alarm(number_of_seconds_to_hammer);
  HammerAllReachableRows(&HammerAddressesStandard, number_of_reads); // passa 1gb e uma referencia ao nucleo do exploit
}
