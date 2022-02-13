set fish_greeting ""

# Aliases

alias grep "grep --color=auto"
alias cat "bat --paging=never"
alias ls "lsd --group-dirs first -a"
alias ll "lsd --group-dirs first -la"
alias tree "lsd --tree"
# alias dotfiles "git --git-dir $HOME/.dotfiles/ --work-tree $HOME"

# Prompt

starship init fish | source

# Shape of the cursor based on vim(over the shell) status

function fish_vi_cursor --on-variable fish_bind_mode
    switch $fish_bind_mode
        case insert
            printf '\e]50;CursorShape=1\x7'
        case default
            printf '\e]50;CursorShape=0\x7'
        case "*"
            printf '\e]50;CursorShape=0\x7'
    end
end

# vim exit cursor corrector (block to doble T)

function vi_exit --on-event fish_prompt
    printf '\e]50;CursorShape=1\x7'
end
