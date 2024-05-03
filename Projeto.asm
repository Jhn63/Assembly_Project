.686
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib

include \masm32\include\msvcrt.inc
includelib \masm32\lib\msvcrt.lib
include \masm32\macros\macros.asm


.data
    opt1_succeed db "Criptografia realizada com sucesso!", 0AH, 0H
    opt2_succeed db "Descriptografia realizada com sucesso!", 0AH, 0H
    opt3_succeed db "Fechando programa", 0AH, 0H

    str_title db "--------- Cifra de Transposicao ---------", 0AH, 0AH, 0H

    str_request_3 db "Entre a chave de transposicao", 0AH, 0H  
    str_request_2 db "Entre o caminho do arquivo de saida", 0AH, 0H
    str_request_1 db "Entre o caminho do arquivo de entrada", 0AH, 0H
    str_options   db "[1]Criptografar [2]Descriptografar [0]Sair", 0AH, 0H
    str_prompt    db ">> ", 0H

    key_numeric dd 8 dup(0)             ;array para receber os digitos da chave

    ;BUFFERS DE LEITURA E ESCRITA
    console_buffer db 64 dup(0)         ;buffer para ler da console
    input_file_buffer db 8 dup(0)             ;buffer para ler do arquivo de entrada
    output_file_buffer db 8 dup(0)             ;buffer para escrever no arquivo de saida
    

    ;PARAMETROS DA CONSOLE
    input_handle dd 0
    output_handle dd 0
    console_count dd 0
    

    ;PARAMETROS DO ARQUIVO
    input_file_handle dd 0
    output_file_handle dd 0
    count_read dd 0        
    count_write dd 0

.code

;FUNÇÃO PARA CONVERTER A STRING DE INPUT_BUFFER
;PARA UM VALOR NUMERICO, RETORNO EM (EAX)


Convert:
    push ebp
    mov ebp, esp
    
    mov esi, [ebp+8]    ; string
    mov edi, [ebp+12]   ; array dword
    xor ecx, ecx        ; Zera o contador ecx

    loop_start:
        mov al, [esi + ecx]    ; Carrega o caractere da string key na posição atual em al
        sub al, '0'            ; Converte o caractere ASCII para valor numérico
        mov [edi + ecx * 4], al  ; Armazena o número convertido na matriz key_numeric

        inc ecx                ; Incrementa o contador
        cmp ecx, 8             ; Compara o contador com 8
        jne loop_start         ; Se ecx não for igual a 8, volte ao início do loop

    pop ebp
ret 8


;FUNÇÃO PARA REMOVER CR DA STRING
RemoveCR:
    push ebp
    mov ebp, esp

    mov esi, [ebp+8]
    proximo:
        mov al, [esi]
        inc esi
        cmp al, 13
        jne proximo
        dec esi
        xor al, al
        mov [esi], al
        
        pop ebp
ret 4

;FUNÇÃO PARA CARREGAR BUFFER DO ARQUIVO DE ENTRADA 
LoadFileBuffer:
    push ebp
    mov ebp, esp
    mov esi, [ebp+8] ; ARQ DE ENTRADA 
    
    invoke ReadFile, esi, addr input_file_buffer, 8, addr count_read, NULL
    pop ebp
ret 4


;FUNÇÃO PARA DECARREGAR CONTEUDO DO BUFFER DO ARQUIVO DE SAIDA
UnloadFileBuffer:
   push ebp
   mov ebp, esp
   mov esi, [ebp+8] ;ARQ DE SAIDA

   invoke WriteFile, esi, addr output_file_buffer, 8, addr count_write, NULL ;;;;;outfile olhar
   pop ebp
ret 4


;FUNÇÃO PARA CIFRAR
Cipher:
    push ebp
    mov ebp, esp

    cifrar:
        invoke ReadFile, input_file_handle, addr input_file_buffer, 8, addr count_read, NULL
        cmp count_read, 0
        je fim_cifrar   

        mov esi, offset input_file_buffer
        mov edi, offset output_file_buffer

        xor al, al
        xor ecx, ecx
        xor ebx, ebx
    
        repetir:
            mov ebx, [key_numeric + ecx * 4]
 
  
            mov al, [esi + ecx]        
            mov byte ptr[edi + 1 * ebx], al

            inc ecx
            cmp ecx, 8
            jne repetir

        invoke WriteFile, output_file_handle, addr output_file_buffer, 8, addr count_write, NULL
        jmp cifrar
    fim_cifrar:

    pop ebp
ret

    
;FUNÇÃO PARA DESCIFRAR

Decipher:
    

ret



;SOLICITA O ARQUIVO DE ENTRADA E SALVA SEU APONTADOR NA VARIAVEL INPUT_FILE_HANDLE
RequestInputFile:
    invoke WriteConsole, output_handle, addr str_title, sizeof str_title, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_request_1, sizeof str_request_1, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr console_buffer, sizeof console_buffer, addr console_count, NULL

    ;tratando a string com o nome do arquivo de entrada
    push offset console_buffer
    call RemoveCR
    
    ;abrindo arquivo
    invoke CreateFile, addr console_buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov input_file_handle, eax
ret



;SOLICITA O ARQUIVO DE SAIDA E SALVA SEU APONTADOR NA VARIAVEL OUT_FILE_HANDLE
RequestOutputFile:
    invoke WriteConsole, output_handle, addr str_request_2, sizeof str_request_2, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr console_buffer, sizeof console_buffer, addr console_count, NULL

    ;tratando a string com o nome do arquivo de saida
    push offset console_buffer
    call RemoveCR

    ;criando arquivo
    invoke CreateFile, addr console_buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov output_file_handle, eax
ret



;SOLICITA A CHAVE PARA CRIPTOGRAFIA
RequestKey:
    invoke WriteConsole, output_handle, addr str_request_3, sizeof str_request_3, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr console_buffer, sizeof console_buffer, addr console_count, NULL

    ;tratando string com a chave de transposição 
    push offset console_buffer
    call RemoveCR

    push offset key_numeric
    push offset console_buffer
    call Convert                ;converte a chave de string de dword
ret



;SOLICITA QUE O USUARIO ESCOLHA UMA OPÇÃO
ShowOptions:
    invoke WriteConsole, output_handle, addr str_options, sizeof str_options, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr console_buffer, sizeof console_buffer, addr console_count, NULL

    ;tratando string com opção escolhida
    push offset console_buffer
    call RemoveCR

    ;convertendo o valor em numerico, retorno em eax
    invoke atodw, addr console_buffer
ret

;MOSTRA O MENU DO PROGRAMA
Menu:
    call RequestInputFile
    call RequestOutputFile
    call RequestKey
    call ShowOptions
        
    cmp eax, 1
        je case_1
    cmp eax, 2
        je case_2

    jmp end_case
        case_1:

            ;push output_file_handle
            ;push input_file_handle   
            call Cipher   

            jmp end_case

       case_2:
       
            call Decipher
            jmp end_case

       end_case:
ret


;O PROGRAMA FECHA QUANDO "SAIR" FOR SOLICITADO

start:
    invoke GetStdHandle, STD_INPUT_HANDLE
    mov input_handle, eax
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov output_handle, eax

    call Menu

    invoke CloseHandle, input_file_handle
    invoke CloseHandle, output_file_handle
    
    invoke WriteConsole, output_handle, addr opt3_succeed, sizeof opt3_succeed, addr console_count, NULL
    invoke ExitProcess, 0
end start