# CSGO-P2C-Dumper - Dirty Implementation
<p align="center">
Want to analyze your favorite CS:GO pay(ste) to cheat?! Look no further!


CSGO-P2C-Dumper is a process memory dumper aimed to target CS:GO internal cheats, while offering additional reversing aid.
</p>

# Features:

- Signature Based Dumping

      - Dumps a section of memory based on a set of popular signatures. This isn't ideal for smaller cheats.
      
- Hook Based Dumping

      - Finding direct JMP's to the cheat module by checking the first couple bytes of commonly hooked functions.
      - Logging the displacement of the handler function (in cheat module) relative to the address started the memory dump.
      - Logging pre&post injection buffer, aswell and post injection decoded assembly.
           
- Allocation Based Dumping

      - Compares allocated memory regions, and dumps the differences.

<details>
  <summary>Images</summary>
  
 ![ikFLJjM](https://user-images.githubusercontent.com/38055313/141925758-433d647d-de26-4319-a1ed-998e5d2a70c2.png)
</details>






# Credits:

- [zydis](https://github.com/zyantific/zydis) (Disassembler)
- [chdr](https://github.com/ch4ncellor/chdr) (Memory Library)



