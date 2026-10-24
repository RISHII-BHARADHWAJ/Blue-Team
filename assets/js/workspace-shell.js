(() => {
  const menu=document.querySelector('.tp-menu');
  if(menu){
    const close=()=>{document.body.classList.remove('tp-nav-open');menu.setAttribute('aria-expanded','false');};
    menu.addEventListener('click',()=>{const open=document.body.classList.toggle('tp-nav-open');menu.setAttribute('aria-expanded',String(open));});
    document.addEventListener('keydown',event=>{if(event.key==='Escape'){close();menu.focus();}});
    document.addEventListener('click',event=>{if(!event.target.closest('.tp-rail,.tp-menu'))close();});
    document.querySelectorAll('.tp-rail a').forEach(link=>link.addEventListener('click',close));
  }
  // Table overflow stays local to the data region, never the entire workspace.
  document.querySelectorAll('main table').forEach(table=>{
    if(!table.parentElement.matches('.table-wrap,.table-scroll,.scroll,.tp-table-scroll')){
      const wrapper=document.createElement('div');wrapper.className='tp-table-scroll';table.before(wrapper);wrapper.append(table);
    }
  });
})();
