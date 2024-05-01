.686
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\masm32.lib


.data
    ok_msg db "Processo concluido com sucesso", 0AH, 0H
    fail_msg db "Ocorreu um erro interno", 0AH, 0H

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
    file_handle dd 0
    out_file_handle dd 0
    
.code

;FUN��O PARA CONVERTER A STRING DE INPUT_BUFFER
;PARA UM VALOR NUMERICO, RETORNO EM (EAX)

RemoveCR:
    mov esi, offset input_buffer
    proximo:
        mov al, [esi]
        inc esi
        cmp al, 13
        jne proximo
        dec esi
        xor al, al
        mov [esi], al   
ret


;MOSTRA O MENU DO PROGRAMA

Menu:
    invoke WriteConsole, output_handle, addr str_title, sizeof str_title, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_request_1, sizeof str_request_1, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr input_buffer, sizeof input_buffer, addr console_count, NULL
    
    call RemoveCR
    invoke CreateFile, addr input_buffer, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    mov file_handle, eax

    invoke WriteConsole, output_handle, addr str_request_2, sizeof str_request_2, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr input_buffer, sizeof input_buffer, addr console_count, NULL

    call RemoveCR
    invoke CreateFile, addr input_buffer, GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    mov out_file_handle, eax

    invoke WriteConsole, output_handle, addr str_request_3, sizeof str_request_3, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr input_buffer, sizeof input_buffer, addr console_count, NULL

    call RemoveCR
    invoke atodw, addr input_buffer

    invoke WriteConsole, output_handle, addr str_options, sizeof str_options, addr console_count, NULL
    invoke WriteConsole, output_handle, addr str_prompt, sizeof str_prompt, addr console_count, NULL
    invoke ReadConsole, input_handle, addr input_buffer, sizeof input_buffer, addr console_count, NULL

    call RemoveCR
    invoke atodw, addr input_buffer
ret


;O PROGRAMA FECHA QUANDO "SAIR" FOR SOLICITADO

start:
    invoke GetStdHandle, STD_INPUT_HANDLE
    mov input_handle, eax
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov output_handle, eax

    mostrar_menu:
    
        call Menu
        cmp eax, 0
        
    jne mostrar_menu

    invoke WriteConsole, output_handle, addr ok_msg, sizeof ok_msg, addr console_count, NULL
    invoke ExitProcess, 0
end start