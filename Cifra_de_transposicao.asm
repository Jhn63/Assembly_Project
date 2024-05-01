.686
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib


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

    input_buffer db 64 dup(0)

    ;PARAMETROS DA CONSOLE
    input_handle dd 0
    output_handle dd 0
    console_count dd 0

    ;PARAMETROS DO ARQUIVO
    buffer_key dd 0
    file_handle dd 0
    out_file_handle dd 0
    
.code

;FUN플O PARA CONVERTER A STRING DE INPUT_BUFFER
;PARA UM VALOR NUMERICO, RETORNO EM (EAX)

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


;FUN플O PARA LIMPA BUFFER DA CHAVE
CleanKeyBuffer:
   push ebp
   mov ebp, esp

   

   pop ebp 
ret 4

;FUN플O PARA TRATAR A CHAVE
Getkey:

ret

;FUN플O PARA CIFRAR
Cipher:
    
ret

;FUN플O PARA DESCIFRAR
Decipher:
    
ret



;SOLICITA O ARQUIVO DE ENTRADA E SALVA SEU APONTADOR NA VARIAVEL FILE_HANDLE
RequestInputFile:
    invoke WriteConsole, output_handle, addr str_title, sizeof str_title, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_request_1, sizeof str_request_1, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr input_buffer, sizeof input_buffer, addr console_count, NULL
    
    push offset input_buffer
    call RemoveCR
    invoke CreateFile, addr input_buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov file_handle, eax
ret



;SOLICITA O ARQUIVO DE SAIDA E SALVA SEU APONTADOR NA VARIAVEL OUT_FILE_HANDLE
RequestOutputFile:
    invoke WriteConsole, output_handle, addr str_request_2, sizeof str_request_2, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr input_buffer, sizeof input_buffer, addr console_count, NULL

    push offset input_buffer
    call RemoveCR
    invoke CreateFile, addr input_buffer, GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov out_file_handle, eax
ret



;SOLICITA A CHAVE PARA CRIPTOGRAFIA
RequestKey:
    invoke WriteConsole, output_handle, addr str_request_3, sizeof str_request_3, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr input_buffer, sizeof input_buffer, addr console_count, NULL

    push offset input_buffer
    call RemoveCR
    invoke atodw, addr input_buffer
    mov buffer_key, eax
ret



;SOLICITA QUE O USUARIO ESCOLHA UMA OP플O
ShowOptions:
    invoke WriteConsole, output_handle, addr str_options, sizeof str_options, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr input_buffer, sizeof input_buffer, addr console_count, NULL

    push offset input_buffer
    call RemoveCR
    invoke atodw, addr input_buffer
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

    invoke WriteConsole, output_handle, addr opt3_succeed, sizeof opt3_succeed, addr console_count, NULL
    invoke ExitProcess, 0
end start